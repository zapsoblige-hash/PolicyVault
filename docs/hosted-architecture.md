# PolicyVault Hosted Web Architecture

**Status: DESIGN (Phase A of the Hosted Web Architecture + Security
checkpoint, 2026-08-23).** This document authorizes NOTHING to be
deployed. Production hosting, domain cut-over, and the hosted-capable
public release each require separate explicit owner authorization
(directive §2/§38). Companion document: `docs/hosted-threat-model.md`.

Baseline: public source release `v0.4.1`
(github.com/zapsoblige-hash/PolicyVault, commit `f3430bec…`); private
engineering tree `~/policyvault` (no remote). Frozen covenants: v0.4
`8f87deab…`, v0.4.1 `421bfed8…` — hosted work never changes
consensus-visible bytes (directive §29).

## 1. Objective and the non-custodial invariant

Operate PolicyVault as a public web application WITHOUT becoming a
custodian and WITHOUT weakening the covenant security model. The primary
security objective (directive §3, restated as the design invariant):

> A complete compromise of PolicyVault's hosted infrastructure must not
> give the attacker unilateral authority over users' vault funds.

Hard rules the architecture is built around:

- NO user seed phrases, private keys, recovery phrases, owner keys,
  production delegate/agent keys, or approver keys on any server, ever.
- NO server-side hot wallet that can authorize covenant transitions.
- All covenant-authorizing signatures are produced in the user's wallet
  (KasWare) in the user's browser, over frozen transaction bytes.
- The server coordinates, validates, persists, preflights, broadcasts
  ALREADY-SIGNED transactions, and reconciles against chain truth.
- Kaspa consensus remains the funds-security boundary. The hosted layer
  adds a TENANCY/METADATA authorization boundary on top — it never
  substitutes for covenant enforcement.

## 2. Topology

```
Internet
   |
Cloudflare  (DNS + DNSSEC, TLS edge, CDN for public static, WAF,
   |         DDoS protection, edge rate limits, origin shielding)
   |
   +---------------------------+----------------------------+
   |                           |
policy-vault.org      app.policy-vault.org
static landing/docs       hosted application (same-origin UI + /api)
(public static, cacheable)     |
                          Cloudflare Tunnel (preferred; see §8)
                               |
                     App/API host (DigitalOcean SFO3, private VPC)
                       node.js policyvault server (non-root container)
                          |                    |
                 private VPC network    private VPC network
                          |                    |
                 Managed PostgreSQL      kaspad host
                 (private-only,          (trusted RPC bound to VPC
                  app role only)          only; public P2P only;
                                          --utxoindex; default
                                          standardness; version-checked)
```

- The database and the kaspad JSON/Borsh RPC are NEVER internet-reachable.
- The browser sees ONE origin per surface: `app.policy-vault.org`
  serves both the UI and `/api/...` (same-origin model, §4).
- `policy-vault.org` is a purely static marketing/docs site with no
  API and no session — cacheable at the edge.
- **Production domain (owner-selected and owned, recorded 2026-08-23):
  `policy-vault.org`**, with the hosted application at
  `app.policy-vault.org` and the API under
  `https://app.policy-vault.org/api/...`. The domain enters application
  code ONLY as configuration (the configured application origin), never
  as scattered literals. **DOMAIN OWNED ≠ DNS CONFIGURED ≠ HOSTED
  PRODUCTION DEPLOYMENT AUTHORIZED** — no DNS records exist, no
  Cloudflare zone is configured, no origin is exposed, and deployment
  remains gated on the owner's separate explicit authorization.

## 3. Provider evaluation (directive §6)

### Edge / domain: Cloudflare (evaluated separately)

Chosen for: registrar+DNS+DNSSEC in one place, universal TLS, always-on
DDoS protection at the free/low tier, WAF and rate-limit rules, Tunnel
(origin never needs a public inbound port), and no per-request charge at
expected volumes. Risks accepted and mitigated: Cloudflare terminates
TLS (sees plaintext) — acceptable because the server never holds keys or
secrets-equivalent user material and all covenant authority is
end-to-end (wallet-signed frozen bytes verified by consensus, not by
transport); cache misconfiguration — mitigated by the §27 route
classification (API = no-store + cache-bypass rules, tested).

### Compute: DigitalOcean vs Hetzner Cloud vs Fly.io

| Criterion | DigitalOcean | Hetzner Cloud | Fly.io |
|---|---|---|---|
| Node.js runtime / persistent process | Plain VMs (Droplets) — full control | Plain VMs — full control | Fly Machines (micro-VMs from Docker images) — supported |
| Private networking | VPC per region, free intra-VPC | Private Networks, free intra-net | Private 6PN WireGuard mesh |
| Persistent storage | Block volumes, snapshots | Volumes, snapshots | Fly Volumes (fewer guarantees, thinner ops story) |
| Managed PostgreSQL | YES (managed, private-network, PITR, automated backups) | NO first-party managed PG (self-host or third party) | YES — first-party "Managed Postgres" (automatic backups/recovery, HA failover, private 6PN network, encrypted at rest/in transit; corrected 2026-08-23 — an earlier revision of this table wrongly said Fly lacked a managed offering) |
| Backup/restore | Managed PG automated daily + PITR; volume snapshots | Self-managed (pgBackRest/wal-g etc.) | Managed Postgres: automatic backups/recovery; other volumes self-managed |
| Firewalling | Cloud Firewalls (VPC + tag scoped) | Cloud Firewalls | Effectively private-by-default; ingress via Fly proxy |
| US-West presence | SFO3 | US locations: Hillsboro (OR) + Ashburn (East) | Multiple US regions incl. West |
| Docker/container | Yes (we control the VM) | Yes | Native (image-based deploys) |
| kaspad suitability (sync IO, disk growth, stable peer P2P) | Good: dedicated droplet + volume | Good and cheapest per GB/vCPU | Poor fit: micro-VM model, volume + long-sync ergonomics, P2P ingress cost/complexity |
| Operational complexity | Low-moderate (plain VMs + one managed service) | Moderate (everything self-managed incl. PG) | Low for app + managed PG; HIGH for the kaspad tier (proxy-fronted micro-VM platform vs. a chain node needing direct P2P + big persistent volume) |
| Cost (low adoption) | ~$40–70/mo (see §13) | ~$20–40/mo | ~$25–50/mo but PG/kaspad ops risk |
| Cost (moderate adoption) | ~$100–170/mo | ~$60–110/mo | scales fine for app tier only |
| Failure recovery | Managed-PG failover option; snapshot restore | manual | app-tier good; state-tier manual |
| Lock-in | Low (plain VMs + standard PG) | Low | Moderate (platform-specific deploy/ops) |
| Security controls | VPC, firewalls, managed-PG private endpoints, team 2FA | equivalents, fewer managed pieces | platform-managed ingress; less control at the network layer |

**Recommendation (owner-approved 2026-08-23, now frozen for this
checkpoint): DigitalOcean SFO3 for compute + DigitalOcean Managed
PostgreSQL; Cloudflare for edge/domain.** Rationale (not sticker
price): the single biggest operational funds-safety risk in the hosted
stack is DURABLE STATE (requests/claims/receipts) — a managed
PostgreSQL with automated backups, point-in-time recovery, and
private-network-only endpoints removes the highest-consequence
self-management burden. Fly.io DOES offer a comparable first-party
Managed Postgres (table corrected 2026-08-23); DigitalOcean remains
preferred because PolicyVault's topology has TWO stateful tiers and one
of them is a chain node: a dedicated kaspad host needs a plain VM with
a large persistent volume, direct public P2P ingress on its own port,
and explicit network-layer firewalling — a natural fit for droplets +
VPC + Cloud Firewalls, and a mismatch for Fly's proxy-fronted micro-VM
platform. Keeping app, kaspad, and managed PG as one provider's VPC
with uniform firewall semantics avoids a split-provider private-network
bridge that would add operational and security complexity without a
compensating gain. Hetzner is materially cheaper but has no
first-party managed PG (and its US regions sit slightly off the SFO3
preference); it remains the documented fallback if cost pressure ever
dominates — the design is plain-VM + standard-PG portable by
construction.

## 4. Same-origin model (directive §5)

- One browser origin for the app: `https://app.policy-vault.org`
  serves the static UI AND `/api/v1/...` from the same host through the
  same edge zone. No CORS grants are needed or given.
- `Access-Control-Allow-Origin: *` stays permanently removed (the
  loopback CORS finding from Checkpoint I must never regress). The
  hosted API sends NO CORS headers at all: same-origin requests don't
  need them; cross-origin browsers then fail closed.
- State-changing requests additionally require a verified `Origin` (or
  `Sec-Fetch-Site: same-origin`) match against the configured public
  origin, plus Host validation against an allowlist — details and
  hostile cases in the threat model §6 and directive §16 test list.
- The static landing site (`policy-vault.org`) has no API, no
  cookies, no session — it can never become a CSRF or cache-leak
  surface.

## 5. Trusted Kaspa node tier (directive §12)

- Dedicated kaspad host (same VPC), one per network environment:
  staging = testnet-10, production = mainnet. Never shared processes,
  never shared data roots.
- Startup + continuous health checks (already implemented in the SDK's
  `connectVerified` and the server's status gate): exact `networkId`
  match, `isSynced === true`, `hasUtxoIndex === true`, server version
  logged; the app REFUSES live operations otherwise (fail-closed —
  proven behavior, observed again during the mainnet smoke).
- Standardness: default policy only; `accept_non_standard` must never be
  set (v0.4.1 is standardness-compliant by design: 13 static sig-ops).
- RPC exposure: JSON wRPC (mainnet 18110 / testnet-10 18210) and Borsh
  (17110 / 17210) bind to the VPC-private interface ONLY; provider
  firewall additionally restricts them to the app host. PolicyVault
  speaks JSON wRPC.
- P2P: the only publicly exposed kaspad surface, restricted to the P2P
  port alone (mainnet 16111 / testnet-10 16211 defaults), because a
  node needs public peers to stay healthy. No admin/metrics interfaces
  public.
- The app treats its node as the truth source; it must never silently
  fall back to a public RPC endpoint (existing config rule — explicit
  `KASPA_RPC_URL` on mainnet — is preserved verbatim in hosting).

## 6. Durable persistence: PostgreSQL (directive §11)

Hosted multi-user production replaces the local JSON data root as the
source of truth. Target: **PostgreSQL 16+, DigitalOcean Managed PG,
private endpoint, least-privilege app role, TLS transport.**

Design rules (full schema lands in implementation Phase C):

- Tables mirror the EXISTING durable objects one-to-one — vaults
  (manifest + registry), wallet requests, approvals, transition claims,
  submission claims, receipts, audit events, organizations, members,
  sessions, rate-limit counters — plus `tenant_id` ownership columns
  (see threat model §5 for the tenancy rules).
- The v0.2→v0.4.1 request/claim/reconciliation INVARIANTS survive
  unchanged: single-writer transition claims per predecessor outpoint
  (UNIQUE constraint), submission claims held until chain proof,
  crash-consistent state transitions (DB transactions replace the
  fsync-rename discipline), idempotent reconcile, fail-closed on
  ambiguity. Semantics are ported, never redesigned casually.
- Concurrency: `SERIALIZABLE` or explicit row locks (`SELECT … FOR
  UPDATE`) around request state transitions; UNIQUE constraints as the
  final arbiter for claim races (the DB enforces what the filesystem
  lock enforced).
- Equivalence tests (directive §11): a persistence-layer test suite runs
  the SAME behavioral matrix (crash points, duplicate submit, claim
  conflict, stale claim release) against the PG layer and asserts the
  same outcomes the JSON layer proved. The live crash/concurrency
  matrices re-run against a PG-backed server in staging.
- Backup/DR: automated daily backups + PITR (managed feature), plus a
  REAL restore exercise as a PASS requirement (directive §23): restore
  into an isolated instance, point a fresh app at it, prove
  vault/request/activity state reconciles against chain truth with no
  duplicate submission and no wrongly-released claim. Targets: RPO ≤ 24h
  worst-case via daily backup with PITR narrowing to minutes where
  available; RTO ≤ 4h operator-driven; retention ≥ 7 daily + the
  pre-upgrade snapshot.
- The local JSON mode REMAINS supported for the self-hosted single
  operator product (it is released and documented); hosted-PG is an
  additional persistence backend behind the same durable-state
  interface, selected by configuration. Unknown backend → fail closed.

## 7. Wallet-bound authentication + sessions (directive §8/§9)

**Verified wallet primitive (from KasWare source, kasware-wallet/
extension@main, 2026-08-23 — NOT from memory):** the injected provider
exposes `kasware.signMessage(text, params?)`; the background controller
passes it verbatim to the keyring, and `SimpleKeyring.signMessage` calls
**kaspa-wasm `signMessage({ message, privateKey, noAuxRand })`**
(`src/background/service/keyringclass/simple-keyring.ts` imports
`signMessage`/`verifyMessage` from `kaspa-wasm`). Type selection: normal
keyrings sign **Schnorr**; only the Tangem hardware address type
defaults to ECDSA (`wallet.ts signMessage`, addressType
`KASPA_TANGEM_44_111111`); callers may force `type: "schnorr"`.
KasWare also exposes `getPublicKey()` and a `verifyMessage` provider
method.

**Authoritative semantics (rusty-kaspa `wallet/core/src/message.rs` +
`crypto/hashes/src/hashers.rs`):** the signed digest is the keyed
blake2b domain hash `PersonalMessageSigningHash`
(`b"PersonalMessageSigningHash"`) of the UTF-8 message; the signature is
BIP-340 Schnorr (64 bytes) verified against the x-only public key.
**Domain separation is structural:** transaction sighashes use the
distinct `TransactionSigningHash` domain, so a personal-message
signature can NEVER validate as a transaction/covenant signature and
vice versa — authentication signatures cannot be replayed into funds
authority. Empirically verified against OUR pinned kaspa-wasm build
(64-byte sig verifies via x-only and full pubkey; tampered message and
wrong key reject).

**Challenge/response session flow:**

1. Browser requests a challenge: `POST /api/v1/auth/challenge` with the
   wallet address. Server issues `nonce = 32 random bytes (hex)` from
   CSPRNG, stores `{nonce, address, networkId, issuedAt, expiresAt =
   issuedAt + 5 min, used: false}`.
2. The challenge TEXT is structured and self-describing (what the human
   sees in the KasWare popup is the message itself):
   `PolicyVault authentication\norigin: https://app.policy-vault.org\nnetwork: <networkId>\naddress: <address>\nnonce: <hex>\nissued: <RFC3339>\nThis signature only signs you in. It cannot move funds.`
3. Browser calls `kasware.signMessage(text, { type: "schnorr" })` and
   `kasware.getPublicKey()`, then `POST /api/v1/auth/verify`.
4. Server verification (all fail-closed): nonce exists, unused, unexpired
   (single-use — marked used atomically); message text reconstructs
   EXACTLY server-side (never trusted from the client); pubkey→address
   derivation matches the claimed address AND the canonical
   per-network prefix (existing `address-identity.js`); network equals
   the server's configured network; kaspa-wasm
   `verifyMessage({message, signature, publicKey})` returns true.
   ECDSA-type accounts (Tangem) are refused for authentication in v1
   with a clear error (documented limitation; can be added later behind
   the same interface with `verifyMessageECDSA`).
5. On success the server creates a session: 256-bit random id (CSPRNG),
   server-side record `{sessionId(hashed at rest), walletAddress,
   xOnlyPubkey, networkId, createdAt, lastSeen, absoluteExpiry ≤ 24h,
   inactivityExpiry 30 min, revoked: false}`. The session id is
   delivered ONLY as a cookie: `Secure; HttpOnly; SameSite=Strict;
   Path=/api` — never in a URL, never readable by page JS.
6. Rotation: a fresh session id is issued at every authentication (no
   fixation); logout revokes server-side; wallet ACCOUNT or NETWORK
   switch in the browser invalidates the session (the existing
   wallet-session security-event handling extends to the hosted
   session: the client drops it and the server sees a mismatch and
   refuses).

**Authentication ≠ covenant authority (directive §8, non-negotiable):**
the session authorizes TENANCY-scoped reads and metadata writes only.
Every covenant operation continues to independently validate the
required signer (owner/agent/approver of THAT vault) against the frozen
transaction bytes exactly as today — a valid session for wallet A grants
zero signing authority and zero cross-tenant visibility.

CSRF posture: `SameSite=Strict` cookie + strict Origin/Sec-Fetch-Site
verification on every state-changing request + same-origin API with no
CORS grants; hostile-case tests per directive §16.

## 8. Ingress and TLS (directive §19)

**Preferred: Cloudflare Tunnel** (`cloudflared` on the app host,
outbound-only connection to the edge). The origin then has NO public
inbound HTTP port at all — direct-to-origin bypass, origin-IP discovery,
and origin DDoS cease to exist as surfaces; TLS to the edge plus an
authenticated tunnel to the origin satisfies "no plaintext public origin
traffic". Trade-off documented: cloudflared becomes a runtime dependency
(auto-reconnecting, packaged in the compose stack) and a Cloudflare
control-plane outage removes ingress (acceptable: the self-hosted
product remains available to any user, and the outage cannot endanger
funds — availability-only). Fallback if Tunnel is rejected during
implementation: origin binds 443 with a Cloudflare Origin CA
certificate, provider firewall allowlists Cloudflare IP ranges only, and
Authenticated Origin Pulls (mTLS) enforces that requests really came
through Cloudflare.

## 9. Firewall model (directive §20)

| Host | Public | VPC-private |
|---|---|---|
| App/API | NOTHING inbound (Tunnel) — or 443 Cloudflare-only in fallback | → PG 25060 (managed endpoint), → kaspad JSON wRPC |
| kaspad | P2P port only | JSON/Borsh wRPC from the app host only |
| Managed PG | nothing (private endpoint, provider-enforced) | app DB role from app host only |
| SSH/admin | disabled publicly; provider console + short-lived allowlist when unavoidable | — |

PASS evidence requires live connection tests from allowed and disallowed
vantage points (directive §20: "prove with connection tests").

## 10. Secrets, logging, headers, cache

**Secrets (directive §21):** DB credentials, session-cookie signing/
pepper values, tunnel credentials, deploy tokens — injected via provider
secret/env mechanisms; never committed, never in browser JS, never
logged, never in release archives; staging secrets rotate before
production. There are NO wallet-key secrets by construction. `.env*`
stays gitignored in both trees.

**Logging (directive §22):** structured lines with request id, route
class, status, timing, coarse error class, network, vault/request ids,
public txids. NEVER: session cookies/tokens, auth signatures, full
bodies, or any key material (none exists server-side). A redaction
layer scrubs known-sensitive fields before emission, with tests that
assert forbidden patterns never appear in captured log output
(sabotage-style: neutralize the redactor → the test must go red). No
analytics/trackers (directive §15); no personal data beyond what
operation requires (wallet addresses and public chain data).

**Security headers (directive §26):** keep the existing strict set
(CSP `default-src 'self'; script-src 'self'` — no inline/eval,
frame-ancestors 'none', X-Content-Type-Options nosniff,
Referrer-Policy no-referrer, restrictive Permissions-Policy) and add
hosted-only `Strict-Transport-Security: max-age=31536000;
includeSubDomains` once TLS is terminal. API responses:
`Cache-Control: no-store` (already the shipped behavior).

**Cache classes (directive §27):** PUBLIC STATIC (landing site, hashed
assets) — edge-cacheable; PUBLIC READ (none initially — health/status
stay uncached); PRIVATE/API (`/api/*`) — `no-store` at origin PLUS an
edge cache-bypass rule for the path, with a cross-user cache-leak test
in the hostile matrix.

## 11. Rate limiting and resource caps (directive §17/§18)

Layered: Cloudflare edge rules (volumetric, bot, body-size) in front of
application limits keyed by IP, session, wallet address, and endpoint
class — strictest on the expensive classes: build, preflight,
reconcile, RPC-backed reads, request creation, approval submission,
transaction submission. Application-level semaphores bound RPC
concurrency and VM-preflight concurrency (queue + reject-with-429 when
saturated, never unbounded). Hard input caps (many already shipped:
1 MB JSON body cap, traversal guard, org-name length): JSON depth/size,
string lengths, open requests per vault and per wallet (abandoned-
request quota with explicit cancellation), approval count (≤10 by
covenant anyway), pagination bounds, DB rows per request. Rate-limit
rejections are pure refusals — they never mutate covenant state (a
throttled submission keeps its claims exactly as an ambiguous
submission does; reconcile remains the recovery path). Slow-client and
flood tests are part of the hostile matrix.

## 12. Container / deployment artifact + staging (directive §24/§25)

- `Dockerfile` (app): pinned Node LTS base by digest, non-root user,
  read-only rootfs where practical, healthcheck on `/api/v1/health`,
  no secrets baked in. kaspad image: pinned release binary, its own
  volume. `docker-compose.hosted.yml`: app + postgres + kaspad +
  cloudflared for LOCAL hosted-simulation and staging (this is also how
  the hostile multi-user matrix runs reproducibly).
- Staging (allowed, still not public production): testnet-10 ONLY, its
  own hostname/DB/secrets/node/data, clearly labeled, no real value,
  dev signer and test hooks ABSENT from anything labeled staging-prod
  parity (the existing startup refusals already enforce this on
  mainnet configs).

## 13. Cost model (directive §32, list prices 2026, rounded)

| Item | Prototype/staging | Low-adoption prod | Moderate prod |
|---|---|---|---|
| Domain | ~$10–15/yr | same | same |
| Cloudflare | Free plan | Free–Pro ($20/mo if WAF depth wanted) | Pro $20/mo |
| App droplet | $12–24/mo (2GB–4GB) | $24/mo (4GB) | $48/mo (8GB) |
| kaspad droplet + volume | $24/mo + $10 (100GB vol) | $48/mo (8GB RAM) + volume sized to network growth | $48–96/mo + volume |
| Managed PostgreSQL | dev tier $15/mo | $30–60/mo (with standby: 2×) | $60–120/mo + standby |
| Backups/snapshots | ~20% of droplet cost | same | same |
| Bandwidth | included pools suffice | included | watch egress |
| Monitoring | provider-included + uptime ping free tier | same | same |
| **Total** | **~$65–90/mo** | **~$130–180/mo** | **~$200–300/mo** |

Isolation/security is never traded for these amounts (directive §32);
the Hetzner fallback halves compute costs if that ever matters.

## 14. Implementation phase plan (after owner review of Phase A)

- **B — auth + sessions:** challenge/verify endpoints, session store,
  cookie policy, wallet-session integration, hostile auth tests.
- **C — tenancy + PostgreSQL:** ownership model on every object, PG
  schema + migrations, durable-state equivalence tests, JSON↔PG
  backend selection, crash/concurrency matrix on PG.
- **D — origin/CSRF/limits:** Origin/Host verification, rate limiters,
  resource caps, header set, hostile origin/DoS tests.
- **E — containers + staging + backup exercise:** images, compose,
  staging bring-up (testnet-10), REAL backup/restore evidence. **DONE
  2026-08-24** — `docs/hosted-deployment.md`, `docs/hosted-backup-restore.md`,
  `docs/hosted-staging-evidence.md`; fail-closed startup order,
  liveness/readiness, real pg_dump/restore + chain-truth DR, measured
  Cloudflare Tunnel ingress. **Final evidence CLOSED by Phase E-R
  (2026-08-24/25, `docs/hosted-phase-e-r-evidence.md`): the ACTUAL
  image was built on a real Docker Engine, the every-layer privacy
  scan ran CLEAN, the real container stack passed every runtime check,
  and the full acceptance ran 39/39 through a REAL Cloudflare Quick
  Tunnel fronting the actual PolicyVault container, including the
  tunnel-failure test. PHASE E — PASS.**
- **F — hostile multi-user matrix + analyses:** directive §28 suite,
  compromised-server/-frontend re-verification on the hosted build.
  **DONE (PASS) 2026-08-25** — found+fixed the wallet-request/audit
  tenancy gap (F-1..F-4), full matrix + compromised-component verdicts:
  `docs/hosted-phase-f-security-review.md`; final artifact closure
  (post-F image + in-container cross-tenant proof + 39/39) by Phase
  F-R.
- **G — real-KasWare hosted-like acceptance (HUMAN, testnet-10).**
  **DONE (OWNER-ACCEPTED PASS) 2026-08-25** — full human lifecycle
  chain-proven (auth, create, reject, pause/unpause, account/network
  fail-close, agent spend, 1-of-1 approval flow with distinct human
  identities, terminal recovery); two real defects found and fixed
  (G-1 UX error rendering; G-2 HIGH: approval-package commitment vs
  PostgreSQL jsonb key ordering — canonical serialization fix +
  PG-lifecycle regressions): `docs/hosted-phase-g-kasware-acceptance.md`.
- **H — production runbook + final closeout. DONE 2026-08-25** —
  `docs/hosted-production-runbook.md` is the FINAL launch record:
  exact launch topology (named Cloudflare Tunnel; DigitalOcean SFO3;
  Managed PostgreSQL private endpoint; **kaspad Option A LEAN
  BOOTSTRAP** — operator-controlled trusted node over private
  authenticated transport, honestly classified as an availability/
  operational tradeoff, upgrade path to the dedicated cloud tier
  documented), **INITIAL PRODUCTION APP REPLICAS = 1 pinned** (Phase F
  process-local limiter analysis; scaling gate documented), deploy/
  rollback/incident/monitoring/secrets/cost model, the hosted-mainnet
  fail-closed enablement matrix, the G-2 storage-representation sweep
  (no sibling found), and the 27-question final security re-review
  with evidence. The §13 cost table below is SUPERSEDED by the
  runbook's §18 three-state model (lean launch ≈ $45–75/mo under the
  bootstrap-node decision). Remaining owner gates (unchanged): hosted-
  release push authorization (directive §34) and "Authorize PolicyVault
  hosted production deployment." (directive §38).

Every phase ends with: suites green (SDK 391/391 baseline + new hosted
suites, VM 296/296), both covenant SHAs regenerating byte-identically,
continuation notes updated, checkpoint commit.
