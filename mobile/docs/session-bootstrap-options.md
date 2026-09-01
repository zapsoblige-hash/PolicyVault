# Mobile session bootstrap — options paper

**Status: ANALYSIS ONLY. No implementation in this document or the change
that added it. No decision is made here.** This lays out candidate
architectures for TRACK B / open question 3
(`docs/postlaunch/mobile-architecture-decision.md` §5.1, §8 risk R9, §10
question 3) so the coordinator/owner can freeze a design. Per this
project's standing rules, that freeze is a deliberate, explicit decision
made above the worker level — this paper ends with a recommendation, not
a commitment.

## 0. The problem, restated precisely

`www/js/portable/api.js`'s `SESSION_BOOTSTRAP.status` is `"UNDECIDED"`
today, for a real reason: PolicyVault hosted sessions are **wallet-bound**.
`server/src/auth.js`'s own header states it exactly — "a hosted session
proves only 'this browser holds a live Schnorr-verified login for wallet
X on network Y'" — and that proof is a `PersonalMessageSigningHash`
Schnorr signature (`server/src/auth.js` `verify()`), not a password. So
even *read-only* mobile use needs one signature to start a session, and
this app **holds no signing key of any kind, ever** (`mobile/www/index.html`
footer; `docs/postlaunch/mobile-architecture-decision.md` §4.4, which
puts device-key custody explicitly out of scope for the whole v1
architecture, not just this decision). Every option below has to produce
that one signature — or a narrower substitute credential — from somewhere
that is not this app.

## 1. A cross-cutting fact that constrains every option

Before comparing (a)–(d), one architectural fact applies to **all of
them** and changes the shape of the decision: *how does the phone's HTTP
client, once it has a credential, actually get authenticated per
request?*

- `server/src/auth.js` `buildSessionCookie()` sets the session token
  **only** via `Set-Cookie`, with `HttpOnly; SameSite=Strict` (`Secure`
  too when `authCookieSecure`). The `/auth/verify` route handler
  (`server/src/api.js` line ~631) returns `{ session }` in the JSON body
  — session **metadata**, never the raw token. The raw token exists
  nowhere the app's own JavaScript can read it.
- The vendored HTTP client both the web app and this mobile app share
  (`sdk/src/http-client.js`, copied byte-for-byte into
  `www/vendor/http-client.js` by `mobile/tools/sync-portable.js`) never
  sets `credentials: "include"` on its `fetch` calls (checked directly —
  no occurrence in the file). A `fetch` with no explicit `credentials`
  defaults to `"same-origin"`. That default is *correct and sufficient*
  for the desktop web client, because it and the hosted API are served
  from the same origin (`buildSessionCookie`'s `Path=/api` scoping
  assumes exactly that).
- A Capacitor app in **Mode A** (this app, as built — see
  `docs/postlaunch/mobile-architecture-decision.md` §4.3) serves its
  bundled `www/` from a synthetic local origin
  (`capacitor.config.json`'s `androidScheme: "https"` →
  `https://<something-local>`), not from the hosted API's real origin
  (e.g. `app.policy-vault.org` / whatever serves `/api`). A request from
  that local origin to the hosted API is **cross-site** by every
  definition that matters here. `SameSite=Strict` cookies are not sent on
  cross-site requests, full stop — no client-side flag changes that, it
  is enforced by the cookie itself. And the shared http-client's
  `same-origin` default would not even attempt to carry a cookie
  cross-origin in the first place.

**Consequence: the existing wallet-session mechanism, as it stands today,
cannot authenticate this app's own network calls, regardless of which
bootstrap option below supplies the human signature.** This is a second,
independent problem from "how do we get the phone a session" — call it
the *transport problem* — and every option that ends in "the phone holds
a wallet session cookie" must also answer it. Two structurally different
answers exist:

1. **Mint a bearer-style variant of the session** in addition to (or
   instead of) the cookie, sent by the phone as `Authorization: Bearer
   <token>` the same way the machine-credential path already works
   (`sdk/src/http-client.js` line ~268: `if (token) requestHeaders.
   Authorization = 'Bearer ' + token`). This is new server surface (a new
   response shape, a new secret-handling path) and needs its own review
   — a bearer token is inherently more exfiltratable than an `HttpOnly`
   cookie (any JS in the same process can read and forward it), which is
   a real regression against the current design's XSS posture and must
   be weighed, not waved away.
2. **Make the app's origin match the API's origin** — i.e. run Capacitor
   in a *remote-loaded* configuration (`server.url` in
   `capacitor.config.json`, pointed at the hosted origin) instead of
   Mode A's locally-bundled `www/`. This sidesteps the transport problem
   entirely (same-origin cookies work exactly as they do for desktop) but
   gives up the property Mode A exists for: a store-reviewed, sha256-
   pinned local bundle whose verifier bytes cannot be swapped by the
   server (`mobile/tools/sync-portable.js`'s whole reason for existing).
   It would effectively turn this app into Mode B (`docs/postlaunch/
   mobile-architecture-decision.md` §4.3) for API calls while keeping
   Mode A's bundle-integrity story only for the verifier — a hybrid that
   is not currently analyzed anywhere and would need to be.

A third fact, checked and worth stating plainly rather than assuming:
`server/src/api.js` has **no CORS handling anywhere** (`grep` for
`Access-Control-Allow`/`CORS`/`cors` returns nothing). If option 1 above
is chosen, some layer needs to add CORS headers permitting the app's
origin(s) — possibly already handled at the production edge
(Cloudflare/reverse proxy) outside this repository, but that was not
confirmed as part of this read-only mobile-worktree analysis and should
not be assumed either way.

Every option section below states which of these two transport answers
it needs, because none of them are exempt from this problem.

## 2. Option (a) — Desktop-handoff

**Mechanism.** The user is already signed in on a desktop browser (a real
`HttpOnly` session cookie, same-origin, working today). The desktop page
displays a QR encoding a short-lived, single-use, phone-redeemable
pairing credential. The phone scans it and exchanges it for its own
session.

**Security properties, and how to avoid a bearer-token theft vector.**
This is the exact hazard `docs/postlaunch/mobile-architecture-decision.md`
§5.1(b) already names ("credential transfer... QR shoulder-surfing/
photography, replay, token binding, revocation, what a stolen phone
inherits") and explicitly refuses to ship as a v1 shortcut. A safe design
needs all of:

- **Short TTL.** Minutes, not the session's own lifetime — propose
  60–120 seconds, in the same style as `authChallengeTtlMs` already
  governs auth-challenge freshness.
- **One-time.** Redeemable exactly once. `server/src/auth.js`'s
  `challengeClaim`/`challengeConsume` (atomic CAS, correct even across
  multiple app processes under `PgAuthStore`) is the *exact* primitive
  needed here and should be reused, not reinvented — this is a "same
  shape, different payload" problem, not a new one.
- **Audience-bound.** The pairing record should carry the same
  `networkId` binding `auth.js` challenges already carry
  (`AUTH_NETWORK_MISMATCH`), so a testnet-10 pairing can never redeem a
  mainnet session or vice versa.
- **Scoped down, not equal.** The resulting mobile session should default
  to **read-only** scopes (reuse `server/src/scopes.js`'s existing
  `read:*` scope set — the same list machine credentials already use),
  not a full copy of the desktop session's authority. A stolen QR then
  yields, at worst, read access for a couple of minutes before it either
  gets redeemed or expires unused — never a spend-adjacent capability.
- **Possession proof — genuinely open, and the weakest without new
  crypto.** Two non-cryptographic mitigations that fit the codebase's own
  "no custom cryptography" discipline (`server/src/auth.js` header:
  *"No custom cryptography is implemented here"*): (i) the TTL + one-time
  claim above already bound the exposure window tightly; (ii) a
  human-visible short confirmation code shown on the desktop screen that
  the phone must also submit at redemption time (like a device-linking
  PIN) — this defeats a QR that was only *photographed* without the
  attacker also seeing the desktop screen at redemption time, and needs
  no asymmetric crypto, just a second server-side equality check next to
  the pairing record. A *true* possession proof (the phone signs a
  redemption challenge with a key it just generated, DPoP-style) is
  stronger but is a genuinely new client capability — this app currently
  generates no keys of any kind — and would need its own review before
  being called safe, exactly as §5.1(b) already warns.

**Custody implications.** None of this ever gives the server, or any
new component, custody of a signing key. The pairing credential is an
**API-session** capability only — identical in kind to the existing
session cookie's own limits (`server/src/auth.js` header: *"AUTHENTICATION
!= COVENANT AUTHORITY... every covenant operation keeps its own
independent signer validation over frozen transaction bytes"*). This
property is unconditional across every option in this paper and is not
repeated below.

**Server-side changes required (named, not vague).**
- A new store record type + TTL sweep, sibling to `MemoryAuthStore`/
  `PgAuthStore` in `server/src/auth.js` (or a new module,
  e.g. `server/src/mobile-pairing.js`, following the exact same
  interface shape) for pairing records.
- A new authenticated route, e.g. `POST /api/v1/auth/mobile-pairing/init`
  in `server/src/api.js` near the existing `/auth/verify` handler (~line
  618), reachable only with a live desktop session cookie, minting a
  pairing record and returning it in the **JSON body** (never a cookie —
  it must be QR-encodable).
- A new **unauthenticated** redemption route, e.g. `POST /api/v1/auth/
  mobile-pairing/redeem`, that claims the pairing record (reusing
  `challengeClaim`/`challengeConsume`'s CAS pattern) and, on success,
  issues a real session the same way `/auth/verify` already does via
  `buildSessionCookie` — so session issuance itself is not duplicated,
  only the new bootstrapping step ahead of it.
- A revocation route mirroring `revokeByToken`, reachable from the
  desktop session, to kill an unredeemed pairing before it is used.
- Resolution of the **transport problem** (§1) — either a bearer-session
  variant or a remote-loaded Capacitor origin — since a freshly-redeemed
  session is useless to this app if it can never be attached to a
  request.
- A new QR document format, encoded through the *already-existing*
  `mobile/www/js/portable/qr-frames.js` (the same frame/reassembly
  machinery `screenSign()` already uses), but with its **own** format
  tag — never reusing `AIRGAP.SIGNING_REQUEST_FORMAT` /
  `SIGNED_TX_FORMAT` (`mobile/www/js/portable/airgap.js`) for a
  different document class. This project's own versioning rule
  (`CLAUDE.md`: "Version everything... Unknown versions FAIL CLOSED")
  applies exactly here.

**UX cost.** Best-case of the four options: one QR scan, no second
device, no repeated per-session friction beyond that. Worst-case: a user
without a desktop session cannot bootstrap mobile at all (chicken-and-egg
— desktop-handoff is a *second* path, never the only one).

**What the completion standard requires before this ships.** Its own
hostile review (§5.1(b)'s own words), specifically covering: QR
shoulder-surfing/photography, replay after expiry-boundary races, what a
lost/stolen *already-paired* phone inherits (session revocation reachable
from desktop), and — new, from this paper's own §1 finding — review of
whatever transport-problem fix is chosen, since that fix changes the
attack surface on every subsequent request, not just the bootstrap
moment.

## 3. Option (b) — On-phone challenge + air-gap signature (QR login)

**Mechanism.** This is `docs/postlaunch/mobile-architecture-decision.md`
§5.1(a), the doc's own v1 recommendation. The phone calls the existing
`POST /auth/challenge` (`server/src/api.js` ~line 613), renders the
returned challenge message as a QR through
`mobile/www/js/portable/qr-frames.js` — the exact machinery
`screenSign()` already exercises for transaction signing, and
`mobile/test/airgap-signing.test.js` already covers (13 tests: framing
round-trip, tamper detection, oversize handling, cross-document mixing
refusal). The CLI signer signs it as a **message**, not a transaction —
`mobile/www/js/portable/signer-capabilities.js`'s `qr-airgap` adapter
already declares `messageSigning: true` in its capability descriptor, so
the adapter roster already anticipated this use case; it is simply not
wired to the auth flow yet. The phone scans/pastes the signature back and
`POST`s it to `/auth/verify`.

**Security properties.** The strongest of the four: no new credential
type, no transfer, no second device, no window of a QR being valid for
anyone but the person who requested it. The signature is bound to the
server-issued nonce exactly like desktop login is (`server/src/auth.js`
`challengeText`/`verify` — "a client-submitted message string is never
accepted", the message is always server-reconstructed).

**Custody implications.** None beyond the unconditional statement in §1
— the CLI signer already holds the key today for transaction signing;
this reuses it for one more, narrower-scoped signature kind ("sign-message"
vs "sign-transaction" are already distinct request kinds in the
Universal Signer Interface per the architecture doc).

**Server-side changes required.** Essentially none — `/auth/challenge`
and `/auth/verify` already exist, are network-and-client agnostic, and
need no new route. The only genuinely required piece is still the
**transport problem** from §1: a freshly-verified session is exactly as
useless to this app here as it is under option (a), for the identical
reason (`SameSite=Strict` + cross-origin native client). This option does
not avoid that problem — it only avoids inventing a *second* credential
type on top of it.

**UX cost — the round-trip, stated honestly.** This is the tradeoff
§5.1(a) already names: **every session start** costs a full air-gap round
trip — render request QR → walk to (or already have open) the CLI signer
→ scan/type it in → sign → scan/paste the response back into the phone.
For a *read-only* glance at a vault this is real friction, repeated every
time the session expires, not a one-time setup cost like (a). The
architecture doc's own mitigation is a longer session TTL bound to a
biometric/Keychain-held session token *on the phone* — which is itself
unbuilt (`mobile/www/js/platform/env.js` `biometricReport()`: "biometric/
Keychain session gating is not implemented in this build") — so today
this cost cannot yet be mitigated the way the doc assumes; that is an
additional, currently-missing piece of this option's real cost, not a
detail.

**What the completion standard requires.** Primarily UX validation (is a
QR-round-trip-per-session tolerable in practice) plus whatever the
transport-problem fix requires, same as (a). No new cryptographic review
is implied — it is the same signing kind the CLI signer already performs,
routed to a different endpoint.

## 4. Option (c) — Native mobile signer integration probes (kasware-mobile)

**Mechanism.** KasWare exists **only as a desktop browser extension**
today (`mobile/www/js/portable/signer-capabilities.js`: *"The KasWare
browser extension is PolicyVault's production signing path on desktop.
Browser extensions do not exist inside a native mobile app, so it cannot
be reached from here"* — this is stated of the app's own **Mode A**
WebView, which by construction receives no injected provider). The one
theoretical native-mobile path is **Mode B**
(`docs/postlaunch/mobile-architecture-decision.md` §4.3): the PolicyVault
*web* client, loaded inside KasWare's Android in-app browser (if one
exists and injects a compatible provider) — never inside this app.

**Status: genuinely unverified, and the codebase is explicit about it, not
hedging.** `signer-capabilities.js`'s `kasware-mobile` adapter entry:
`role: "OPPORTUNISTIC — UNVERIFIED"`, `implementation: "PROBE ONLY"`,
`"No device probe has been performed by this project; nothing about
KasWare mobile is claimed."` The negotiation function
(`negotiateInjectedProvider` in the same file) is real, fail-closed code
— it requires every one of `requestAccounts`, `getPublicKey`,
`getNetwork`, `signPskt` to be present as actual functions on the probed
object, and a reported network of exactly `"testnet-10"` or `"mainnet"`
— but it has **never run against a real device**, so whether KasWare's
Android in-app browser (if it exists in a usable form at all) actually
satisfies that contract is unknown, not merely untested-but-expected-to-
pass.

**Security properties.** If it worked, this would be the best story for
mobile signing specifically (native wallet UX, no air-gap round trip) —
but it is **not this app**. It only applies to the separate Mode B
deployment (the web client opened in another app's browser), so it does
not resolve session bootstrap for the Capacitor app this project is
building in Track B at all. It is included here because it is one of the
four paths named in this paper's scope, not because it currently offers
this app anything.

**Custody implications.** Same unconditional statement as §1 — but note
the residual-trust caveat the architecture doc already states for Mode B:
*"the bundle integrity story is weaker — the user is trusting the served
bytes and their WebView, not a store-reviewed binary."* A session
bootstrapped this way inherits that weaker integrity story too.

**Server-side changes required.** None that this paper can identify —
this path, if it ever becomes real, is a client-side (Mode B) capability
question, not a server auth-flow question; the existing `/auth/challenge`
+ `/auth/verify` pair would presumably still be the mechanism, reached
the normal browser way.

**What the completion standard requires.** A real device probe against
whatever KasWare Android in-app-browser surface actually exists today,
before this option can move past "PROBE ONLY" — and that is a discovery
task, not a design decision this paper can shortcut.

## 5. Option (d) — Machine-identity scoped credentials (interim read-only path)

**Mechanism, and current status: already partially built, and already
wired into this app.** `server/src/machine-identity.js` implements
first-class scoped API credentials, independent of the wallet-session
cookie flow entirely: a `pvmk_`-prefixed bearer token, shown once at mint
time, only its SHA-256 ever persisted, sent as `Authorization: Bearer`
(`sdk/src/http-client.js` line ~268 — the exact mechanism §1 identifies
as the one that already survives the transport problem, because it is a
header, not a cookie). `mobile/www/js/app.js`'s `screenSettings()`
**already has a field for this** — "Machine credential (optional,
read-only testing)" — and `www/js/portable/api.js` already threads it
through to `httpClient.createClient({ token, ... })`. This is the one
option in this paper that requires **no new client code at all**; it
already works today, end to end, for whatever scopes the credential
carries.

**Security properties.** A machine identity is bound at creation to the
**wallet session that created it** (`creatorXOnly`) and inherits exactly
that wallet's tenancy, never more — `server/src/machine-identity.js`'s
own header states existing tenancy checks apply unmodified. Scopes are
**deny-by-default**: an unknown scope string refuses the whole request.
Read-only scopes already exist and are exactly what a mobile read path
needs: `read:vaults`, `read:requests`, `read:governance`, `read:audit`,
etc. (`server/src/scopes.js`). Critically, `server/src/api.js` (~line
667) already refuses to let a machine credential mint *another* machine
credential — *"machine-identity management requires a wallet session,
never a machine credential"* — so this cannot become a privilege-
escalation chain on its own.

**Custody implications.** Same unconditional statement as §1. Also
`vaults:suspend-agents` and every write-shaped scope exist in the same
list (`server/src/scopes.js`) — nothing in the mechanism *prevents*
minting a write-capable mobile credential, so the read-only property here
is a **usage discipline** (mint only `read:*` scopes for a mobile
credential), not a structural guarantee the server enforces for you. That
should be stated to whoever mints one, not assumed.

**Gaps, stated honestly, that keep this "interim" rather than a real
answer.**
- **No credential TTL/expiry today** — `machine-identity.js` has manual
  `revokeCredential`/`revokeIdentity` (`revokedAt`), but nothing
  time-bounds a credential automatically. A credential pasted into a
  phone's Settings screen is valid until someone remembers to revoke it —
  a materially different lost-phone story than a QR-login session that
  naturally expires.
- **It requires the desktop user to go mint one manually** (label it,
  scope it, copy the raw token shown exactly once, paste it into the
  phone) — real friction, and one wrong click could mint a
  broader-than-intended scope set, per the gap above.
- **It is explicitly labeled "read-only testing" in the UI today**, not
  presented as a real onboarding path — because it was never reviewed
  as one. Promoting it to a documented, recommended mobile path (even an
  interim one) is itself a decision this paper does not make.

**Server-side changes required to make this a *reviewed* interim path
(vs. today's ad hoc escape hatch).** A credential-TTL/auto-expiry field
alongside the existing `revokedAt` handling in `machine-identity.js`;
possibly a `MAX_CREDENTIALS_PER_IDENTITY`-style default nudging toward
short-lived mobile credentials; and, if this is the chosen interim
answer, explicit UI copy change in `screenSettings()` that stops calling
it "testing" once it is a sanctioned path.

**UX cost.** One manual mint-and-paste, then works until revoked or
(if the gap above is closed) it expires. No repeated per-session cost —
the opposite tradeoff from option (b).

**What the completion standard requires before calling this "done" rather
than "interim."** Deciding whether unbounded-lifetime bearer tokens
pasted by hand are an acceptable *permanent* mobile answer at all (this
paper's view: they are a reasonable bridge, not a destination — a bearer
token in a mobile app's local storage is a meaningfully different theft
surface than an `HttpOnly` cookie a phone JS context can't even read),
and, if kept, the TTL gap above closed and reviewed.

## 6. Comparison

| | (a) Desktop-handoff | (b) QR login (§5.1a) | (c) kasware-mobile | (d) Machine credential |
|---|---|---|---|---|
| Built today? | No | Auth endpoints exist; not wired to mobile | Probe code exists; never device-tested | **Yes, end to end** |
| New server route(s)? | Yes (2–3) | No | No (client-side only) | No (TTL field only, if hardening) |
| New credential type? | Yes (pairing token) | No (reuses wallet session) | No (uses injected provider) | No (already exists) |
| Resolves the §1 transport problem? | Needs a decision (bearer variant or remote-load) | Needs the same decision | N/A — not this app (Mode B) | **Yes, already** (Bearer header) |
| Per-session UX cost | Low (one scan, once) | **High** (every session) | Unknown (native, if it worked) | None (mint once) |
| Setup UX cost | Needs a live desktop session first | None | None | Manual mint + paste |
| Auto-expiry | Design target (short TTL) | Session TTL (existing) | N/A | **Missing today** |
| New crypto? | Only if possession-proof is strengthened | No | No | No |
| Review burden before shipping | High (full credential-transfer threat model) | Medium (mostly transport-problem review) | Requires real device discovery first | Low (mostly hardening existing gaps) |

## 7. Recommendation — OPEN, not a decision

This paper's assessment, offered as input only:

- **§1's transport problem is the actual blocking question**, not any
  single option — (a), (b), and a from-scratch (c) all inherit it
  identically, and it has not been analyzed anywhere in this codebase
  before this paper. Whatever is decided about session bootstrap, the
  cookie-vs-bearer-vs-remote-load question in §1 needs its own explicit
  answer first, or every other option is unbuildable as designed.
- **(d) is the pragmatic near-term bridge**, precisely because it already
  works end-to-end today and sidesteps §1 entirely (it was never
  cookie-based) — but closing its TTL gap and deciding whether it is
  ever more than a bridge is real, undone work, not a formality.
- **(b) matches the existing architecture decision's own v1
  recommendation** (§5.1a) and needs the least new server surface, at the
  cost of the round-trip UX tax on every session — a tax partially
  masked in the original doc's framing by an unbuilt biometric-session
  mitigation.
- **(a) is the best long-term UX** but is the only option with a real,
  novel credential-transfer threat model to clear, exactly as §5.1(b)
  already warned before this paper existed.
- **(c) is not currently an option for this app** (it targets Mode B, a
  different deployment than the one Track B is building) and needs a
  real device probe before it can be evaluated as anything but
  hypothetical.

**The decision itself — which option(s) to build, in what order, and how
to resolve §1 — is explicitly left OPEN.** Per this project's standing
rules, design freezes happen at the coordinator/owner level, not inside a
bounded worker phase; this paper's job was to make that decision
well-informed, not to make it.

## 8. Sources (exact files read for this analysis)

- `server/src/auth.js` — challenge/session lifecycle, Schnorr
  personal-message verification, cookie policy (`buildSessionCookie`,
  `sessionCookieName`, `SameSite=Strict`/`HttpOnly`/`Secure`).
- `server/src/api.js` — `/auth/challenge`, `/auth/verify` route handlers
  and their exact response shapes; machine-identity route gating; no CORS
  handling found.
- `server/src/machine-identity.js` — scoped bearer-credential mechanism,
  tenancy inheritance, deny-by-default scopes, no credential TTL.
- `server/src/scopes.js` — the `read:*`/write scope list.
- `sdk/src/http-client.js` — `Authorization: Bearer` token handling, no
  `credentials: "include"` anywhere.
- `mobile/www/js/portable/api.js` — `SESSION_BOOTSTRAP` (status
  `UNDECIDED`, the exact two candidates this paper starts from).
- `mobile/www/js/portable/signer-capabilities.js` — `qr-airgap`
  `messageSigning: true`, `kasware-mobile` `"PROBE ONLY"` /
  `"OPPORTUNISTIC — UNVERIFIED"`.
- `mobile/www/js/portable/qr-frames.js`, `mobile/www/js/portable/airgap.js`,
  `mobile/test/airgap-signing.test.js` — the existing, tested QR framing
  and document-envelope machinery this paper proposes reusing.
- `mobile/www/js/platform/env.js` — `biometricReport()` (not implemented),
  the honest capability-report pattern this paper follows.
- `mobile/www/js/app.js` `screenSettings()` — the existing machine-
  credential field, already wired.
- `mobile/capacitor.config.json` — `androidScheme: "https"`, local
  bundled `webDir`, no `server.url` configured today.
- `docs/postlaunch/mobile-architecture-decision.md` §4.3, §4.4, §5.1,
  §8 (R9), §10 (open question 3) — the standing architecture decision
  this paper extends with server-file-level detail, not replaces.
