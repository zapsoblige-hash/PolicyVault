# PolicyVault

**Non-custodial delegated-spending vaults on Kaspa L1 — for people and AI agents.**

PolicyVault lets a vault **owner** hand a spending key to an **agent** — an
employee, a service, a bot, or an AI agent — without handing over control of
the funds. The spending policy is enforced by **Kaspa L1 consensus** through
a covenant: even an agent who bypasses this entire application and talks
directly to a Kaspa node cannot exceed the owner's policy.

The authority model, stated once and everywhere enforced:

> **AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES.
> THE COVENANT ENFORCES. SIGNERS RETAIN CUSTODY.**

## Production status (honest labels)

| Surface | Status |
|---|---|
| **Web / Agent platform** | **PRODUCTION — LIVE** at https://app.policy-vault.org. This release's build is `fullscale-rc30` (buildId `9dbc5f7`, image `sha256:4a6dce6e7646e9aa460340339887e117c48185bf7ecdbcae8c5107c72da8be21`); the served `/api/v1/health` `buildId` is authoritative for which build is active at any moment (`9dbc5f7` = this release; `f217011` = the preceding rc29 build of this same source line, live since 2026-09-09 01:17 UTC). You can also fully self-host |
| Current production source | **PUBLIC — this repository, v1.9.2** (exact identity chain in `PUBLIC_RELEASE_MANIFEST.md`; v1.9.1 remains published unchanged; the prepared candidates v1.6.0 / v1.7.0 / v1.8.0 / v1.9.0 were never published separately and are included) |
| Organizational M-of-N owner root (covenant v0.7) | **COVENANT-BYTE-FROZEN** (2026-09-03) · VM-verified · SDK/production-byte-verified · testnet-verified · **application surface LIVE in the hosted deployment but TESTNET-ONLY** — v0.7 roots cannot be created on mainnet (`GENERATION_NOT_MAINNET_AUTHORIZED`); the mainnet-creatable generation is `policyvault-0.4.1` only |
| Rooted-vault owner operations in the browser (R7-05) + reservation/withdrawal guidance (F-6) | **LIVE in this source (testnet-only surface)** — headless-Chromium evidence on the exact image with a TEST-ONLY dev signer; no real-wallet or human evidence is claimed |
| Hosted tenancy for every route family + generation gate (rc11 remediation) | **LIVE** — closes the rc8 findings (unauthenticated hosted builds, prototype-derived version selection, unsafe mainnet creation of the non-standard v0.4 generation) |
| Post-launch live-stack review corrections (rc29: webhook target policy + DNS transport, SDK transport recovery key, legacy same-effect completion ownership, image/package LICENSE + NOTICE, privacy-safe runtime artifacts, recovery guidance) | **IN THIS SOURCE and in the `fullscale-rc29` image** — every finding of the independent read-only review of the running rc28 stack corrected RED-first with a permanent regression; the hosted deployment carries them once the served buildId reads `f217011`; installed SDK / mobile clients must upgrade for the transport correction |
| Second post-launch review corrections (rc30: webhook response-socket lifetime bound; upstream Silverscript ISC notice beside the compiler and the reference program) | **IN THIS SOURCE and in the `fullscale-rc30` image** — both findings of the independent read-only launch review of the running rc29 stack corrected RED-first with a permanent real-socket regression; the hosted deployment carries them once the served buildId reads `9dbc5f7`; no SDK / mobile client byte changed |
| MCP package (`policyvault-mcp` on npm) | **1.5.0 published** (2026-09-09; registry tarball byte-identical to the audited artifact) and proven against the live API (real stdio initialize, 19-tool catalog with an all-scope credential, least-privilege 2-tool discovery with `read:network`); unchanged by this release — no republish |
| Flagship wave 1 (v1.6.0 / v1.7.0) and wave 2 (v1.8.0) source | **INCLUDED and LIVE where applicable** (see their CHANGELOG entries; v0.6 stays FIXTURE VENUE ONLY / no mainnet swap; x402 facilitator PRODUCTION-READY, NOT deployed; MCP usage telemetry OFF) |
| Covenant protocol v0.6 (atomic composability) | **COVENANT-BYTE-FROZEN** (2026-09-03): VM-verified on the real engine with production bytes and testnet-verified (live testnet-10 SELL + BUY). **FIXTURE VENUE ONLY** — no real DEX venue, no mainnet swap, no server/web/mobile/MCP surface, `deadlineDaa` is a pre-sign boundary and not a consensus expiry, and swaps are not economically viable below roughly 10 KAS. **PolicyVault is not a DEX and will not become one.** See `docs/postlaunch/v0.6-covenant-byte-freeze.md` |
| v0.5 token-controller covenant (byte-frozen) + least-privilege discovery / console correctives + MCP 1.4.2 (v1.5.0) | **LIVE** — production runtime successor `fullscale-rc8` (buildId `1c02162`) deployed and automated-accepted on 2026-09-02: principal-scoped capability discovery, no dev-signer probe on production, zero privileged reads while signed out, opt-in wallet diagnostics; `policyvault-mcp@1.4.2` advertises only the tools a credential's scopes cover (server-side enforcement unchanged). The v0.5 TOKEN CONTROLLER covenant (`contracts/PolicyVault.v0.5.sil`, sha256 `c693aeff…`) ships as SOURCE — COVENANT-BYTE-FROZEN, VM-verified with production bytes and testnet-verified with one live lifecycle; NOT production (no v0.5 surface, no mainnet v0.5 vault). Illustrated onboarding walkthrough (presentation only). See CHANGELOG |
| Distribution: MCP registry, agent examples, self-hosting (v1.4.0) | Source/distribution release — NO runtime change (production keeps buildId `6c3177f`): the MCP server is npm/registry-packaged (`policyvault-mcp`, `io.github.zapsoblige-hash/policyvault`), thin OpenAI-Agents-SDK/LangChain/CrewAI wiring examples ship in `examples/agents/`, and one-command self-hosting ships in `deploy/selfhost.sh` + `docs/selfhost-quickstart.md`; see CHANGELOG |
| Bearer wallet-sessions + native mobile transport (v1.3.0) | **LIVE**: opt-in bearer wallet-session authentication for non-browser clients (authentication only — never signing authority or custody; cookie web auth unchanged), plus the native Android transport (explicit CapacitorHttp at the platform seam; no CORS widening, web client stays strict same-origin). The full bearer lifecycle was proven from the real packaged Android runtime against live production; see CHANGELOG |
| Responsive client + quiet signed-out UX (v1.2.0) | Faster signed-in navigation (retained state, parallel reads, truthful progress states — pending is never success) and no spurious signed-out error toasts; see CHANGELOG |
| Network-identity banner fix (v1.1.1) | The web client's network banner now derives from the server's node-verified `/network/status` and FAILS CLOSED to an explicit UNKNOWN state — never a stale or assumed network; see CHANGELOG |
| In-app documentation discovery (v1.1.0) | Docs link + contextual help in the web client, deep-linking to https://docs.policy-vault.org — presentation-only successor; see CHANGELOG |
| External-approver discovery fix (2026-08-27) | **DEPLOYED + AUTOMATED-ACCEPTED** (fail-closed availability defect, no funds/authority/privacy exposure; see CHANGELOG "Fixed". Acceptance was automated; no human acceptance test is claimed) |
| Covenant protocol v0.4.1 | Mainnet-operational (real mainnet lifecycle evidence; see SECURITY.md for exactly what is proven and how) |
| Covenant protocol v0.5 (token controller) | **COVENANT-BYTE-FROZEN** (2026-09-02): VM-verified on the real engine with production bytes and testnet-verified (live testnet-10 lifecycle, consensus-rejected negatives); **not production** — no server/API/web surface, no mainnet instance; see `docs/postlaunch/v0.5-covenant-byte-freeze.md` |
| Python client, MCP server, x402/AP2 adapters, platform agent API | Shipped; covered by the automated conformance/integration suites in this repository |
| **Native mobile (iOS/Android)** | **DEVELOPMENT — NOT YET PRODUCTION-CAPABLE.** The Android app (full Capacitor project in `mobile/`, incl. the native production transport and bearer sign-in) has been validated on a real emulator against live production — reads, full bearer auth lifecycle, fail-closed negatives — but production signing, store packaging, and camera/QR capture remain pending; do not build custody workflows on it yet |
| Security assurance | **INTERNAL and evidence-based only**: independent internal AI falsification reviews of each exact candidate (the reviewer never repairs its own candidate), hostile / adversarial testing on the real Kaspa script engine with production bytes, RED-first reproduction with permanent regressions, production-shaped mechanical verification, live testnet-10 evidence, exact artifact and frozen-byte verification, and the owner's own live mainnet validation after each deployment. **No external professional security audit has occurred and none is part of PolicyVault's process** (owner policy, 2026-09-05); nothing in this repository claims otherwise |
- **x402 FACILITATOR (`integrations/x402-facilitator/`, 2026-09-02):**
  DESIGN FROZEN (owner-authorized; `docs/postlaunch/x402-facilitator-design-freeze.md`)
  · IMPLEMENTED · UNIT-TESTED · ADVERSARIAL-TESTED · INTEGRATION-TESTED
  (real HTTP service + real PostgreSQL claim store) · TESTNET-VERIFIED
  (real KAS + real frozen-v0.5 token payments on testnet-10;
  `docs/testnet-x402-facilitator-evidence.json`). A separately deployed,
  unprivileged, READ-ONLY chain verification / settlement attestation
  service for the proposed Kaspa scheme `pv-x402-kaspa-exact-upfront/1`
  (network identifiers `kaspa:mainnet` / `kaspa:testnet-10` are
  PolicyVault's provisional CAIP-2-syntax identifiers — no upstream
  registration is claimed). It never signs, broadcasts, escrows, or
  charges. NOT a hosted production service (a separate owner gate); no
  upstream Kaspa x402 scheme exists, so it is not "x402-compatible"
  without that qualification.

## What the covenant enforces (consensus, not software)

- **Owner-controlled vaults** — create, manage, pause, recover, close.
- **Delegated spending** — up to 10 independent agents per vault, each with
  its own policy, spending real KAS within owner-defined limits.
- **Per-transaction caps** and **cumulative periodic budgets**
  (DAA-score-based accounting verified by consensus).
- **Recipient allowlists** — Merkle-committed; an agent can pay only
  owner-approved recipients.
- **M-of-N approvals** above an owner-set threshold.
- **Covenant-controlled fee reserve** — agents need no gas wallet; network
  fees come from a reserve the covenant accounts for exactly.
- **Break-glass owner pause and terminal recovery** — never gated by any
  hosted workflow.

## What the platform adds ABOVE the covenant (hosted coordination, not authority)

- **Intent manifests + independent browser verification** — before any
  signature, the browser re-derives what the transaction does from the exact
  bytes to be signed and refuses on any mismatch (`web/verify-intent.js`,
  `docs/postlaunch/intent-manifest-spec.md`, `docs/postlaunch/browser-verification.md`).
- **Governance** — proposal/approval ceremony (Schnorr-verified,
  domain-separated) for authority-expanding policy changes
  (`docs/postlaunch/governance-spec.md`).
- **Risk pipeline** — restrictive-only configurable review/deny adapters
  (`docs/postlaunch/risk-adapter-spec.md`).
- **Budget reservations, hash-chained audit, webhooks/notifications,
  machine identities + scoped capabilities, idempotency, dry-run simulation**
  (`docs/postlaunch/*`).
- **Universal Signer Interface** with KasWare mapping and an offline CLI
  signer reference (`docs/postlaunch/signer-interface-spec.md`,
  `signer-kasware-mapping.md`, `signer-cli-reference.md`).
- **Agent surfaces**: REST platform API, MCP server, Python client, x402 +
  AP2 payment-protocol adapters — all thin consumers of one deterministic
  core; none holds independent financial authority.

None of this hosted machinery can move funds: every funds-moving signature is
made by the owner's or agent's own wallet over frozen bytes, and Kaspa
consensus checks the covenant regardless of what any server says.

## Repository map

| Path | What it is |
|---|---|
| `contracts/` | The covenant sources (v0.1…v0.6), regenerable byte-identically (`tools/gen_v3.js`, `gen_v4.js`, `gen_v4_1.js`, `gen_v5.js`, `gen_v6.js`) |
| `core/` | Portable deterministic core: model, intent manifests, explanations, governance, risk, signer (v1 + the additive v2 interface), execution attestations, cross-runtime equivalence |
| `sdk/` | The Node SDK: builders, freeze/sign/finalize, VM preflight, submission + chain proof, reconciliation, stores (JSON + PostgreSQL) |
| `server/` | Hosted runtime: API, auth/tenancy/request protection, governance/risk enforcement, audit chain, webhooks, notifications, attestation export, optional MCP telemetry (off), migrations 001–010 |
| `web/` | Browser client + **browser-local independent verification** (`verify-intent.js`, `core-bundle.js`) |
| `mcp/`, `python/`, `integrations/` | MCP server, Python client, x402 + AP2 adapters |
| `conformance/` | One matrix driving JS + Python + MCP + x402 + AP2 through identical scenarios (cross-path byte equivalence) |
| `security/` | Internal adversarial (hostile-AI) test suites over the agent-facing boundaries |
| `mobile/` | Native mobile app (Capacitor Android project + portable web payload, native production transport, bearer sign-in) — DEVELOPMENT status (see above) |
| `tests/vm/` | Real Kaspa VM covenant verification workspace (Rust; TxScriptEngine) |
| `deploy/` | Container build + staging/production/self-host compose examples + env templates + the reproducible deployment pipeline (`deploy/pipeline/`, local proof only) |
| `docs/` | Protocol specs, architecture, threat model, invariants, hosted design, per-surface specs, covenant freeze records |
| `tools/`, `release-signers.json` | Covenant generators, acceptance harnesses, the attestation verifier, and the release manifest/sign/verify tooling (the signer public key is an unfilled `OWNER-TO-FILL` placeholder; no release has been signed) |

## Quick start (self-hosted, testnet-10)

```bash
# prerequisites: Node 20.x; a local Kaspa testnet-10 node with --utxoindex
#   (rusty-kaspa; JSON wRPC on ws://127.0.0.1:18210)
cd sdk && npm ci && npm test          # the SDK suite (serialized)
cd ../server && node src/server.js    # self-hosted mode, JSON persistence
# open http://127.0.0.1:3080 — connect a testnet KasWare wallet
```

Full instructions, including PostgreSQL-backed hosted mode, container builds,
covenant regeneration + byte-identity verification, and the VM suite:
`docs/deployment.md`, `docs/hosted-deployment.md`, `docs/test-plan.md`.
The VM workspace expects sibling checkouts of the public `silverscript` and
`rusty-kaspa` projects (see `tests/vm/` and `tools/stage-vendor.sh`).

## Product policy (permanent)

Free forever, including commercial use — no subscriptions, no transaction
fees, no paid security, no usage caps. No patents on the protocol or its
mechanisms. Apache-2.0. Voluntary support only — KAS donations:
`kaspa:qyppakv5y7kmeynffldl9zshwgkjrl3fy9jjj8wf24v7f64v0gnuragz7ehdqhn`
(public receiving address; nothing in this software ever asks for or handles
donation-wallet keys). Details: `docs/product-policy.md`.

## Security

Read `SECURITY.md` for the security model, the exact claim → enforcement →
test → evidence discipline, what is PROVEN versus DESIGN TARGET, and how to
report vulnerabilities.
