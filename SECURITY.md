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

## External audit status

**No external professional security audit has occurred.** One is planned.
Nothing in this repository or its documentation claims independent
review, and no such claim should be inferred from internal testing depth.

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
