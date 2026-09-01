# Mobile session bootstrap — DESIGN FREEZE (coordinator, 2026-08-28)

Input: `session-bootstrap-options.md` (options paper, source-grounded).
This document freezes the DESIGN DIRECTION for the mobile lane. It does
NOT deploy anything: every server-side element ships default-OFF behind
configuration, and production enablement remains behind the normal
release/promotion gates.

## Frozen decisions

1. **The §1 transport problem is resolved with a BEARER wallet-session
   surface — never by remote-loading the app.** Remote-load (serving the
   app JS from the hosted origin into the WebView so cookies become
   same-origin) is REJECTED permanently for the native client: it would
   replace the byte-pinned, locally-verified packaged payload with
   whatever the server serves, destroying the on-device independent
   verification model (the packaged `www/vendor` pin gate + Build
   integrity screen are load-bearing controls, not conveniences).
2. **Server: wallet-session Bearer tokens as a config-gated sibling of
   cookie sessions.** The SAME Schnorr challenge/verify ceremony
   (`server/src/auth.js`) may, when the client explicitly requests a
   bearer transport at verify time AND the server has
   `POLICYVAULT_AUTH_BEARER_SESSIONS=1` (default OFF, hosted production
   unchanged until a future promotion), return a session token instead
   of a Set-Cookie. Constraints (all mandatory):
   - Same session store, same TTL, same revocation/logout semantics as
     cookie sessions; the token is a random 256-bit value stored only
     as a hash server-side (never logged, never echoed back after
     issuance).
   - Presented ONLY via `Authorization: Bearer` (the existing machine-
     credential header path shows the pattern); never accepted from a
     query string or body.
   - A bearer session carries exactly the same wallet principal and
     scope as the equivalent cookie session — no wider, no narrower;
     tenancy/authz code must not care which transport authenticated
     the principal.
   - Origin/CSRF gate: bearer-authenticated requests remain subject to
     the same request-protection posture EXCEPT the browser-specific
     Origin requirement, which is replaced by the explicit-header
     evidence (mirroring how machine credentials are already treated —
     match that existing discipline exactly; never weaken the cookie
     path).
3. **Bootstrap v1 = QR login (option b)**: the phone fetches an auth
   challenge (unauthenticated, rate-limited path that already exists),
   renders it as the EXISTING tested air-gap document/QR framing, the
   owner signs it with their desktop wallet (KasWare via the web app,
   or the offline CLI signer reference), and the signature returns to
   the phone (QR scan when camera transport lands; manual paste
   fallback today). The phone completes verify with the bearer
   transport. No new credential class, no new crypto, reuses the
   air-gap tamper/binding refusal tests.
4. **Interim bridge stays (option d)**: machine-identity scoped
   credentials remain the read-only testing path; close their TTL gap
   (expiry field honored server-side) as a small hardening item.
5. **Deferred**: desktop-handoff (option a) until its credential-
   transfer threat model gets a dedicated maximum-effort review;
   kasware-mobile probe (option c) until real-device execution exists
   (KVM/device access).
6. **On-phone token handling v1**: memory-only (no persistence to
   WebView storage; allowBackup is already false), short server TTL;
   secure-storage persistence is a LATER, separately-reviewed step.

## Review discipline

Server-side changes touch the hosted auth surface: implementation must
be tests-first (RED on the frozen behavior, GREEN after), must not
modify cookie-session behavior (byte-level regression on existing auth
suites), and the auth diff gets a coordinator maximum-effort review
before any merge off the lane. Production enablement is a separate
future release decision — this lane's work product is code + tests +
evidence, not deployment.
