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
| **Web / Agent platform** | **PRODUCTION — LIVE** at https://app.policy-vault.org (hosted deployment of this source; you can also fully self-host) |
| Current production source | **PUBLIC — this repository** (buildId `1c02162`; exact identity chain in `PUBLIC_RELEASE_MANIFEST.md`) |
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
| External professional security audit | **Has NOT occurred.** Planned. Nothing in this repository claims otherwise |

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
| `contracts/` | The covenant sources (v0.1…v0.4.1), regenerable byte-identically (`tools/gen_v4_1.js`) |
| `core/` | Portable deterministic core: model, intent manifests, explanations, governance, risk, signer, cross-runtime equivalence |
| `sdk/` | The Node SDK: builders, freeze/sign/finalize, VM preflight, submission + chain proof, reconciliation, stores (JSON + PostgreSQL) |
| `server/` | Hosted runtime: API, auth/tenancy/request protection, governance/risk enforcement, audit chain, webhooks, notifications, migrations 001–009 |
| `web/` | Browser client + **browser-local independent verification** (`verify-intent.js`, `core-bundle.js`) |
| `mcp/`, `python/`, `integrations/` | MCP server, Python client, x402 + AP2 adapters |
| `conformance/` | One matrix driving JS + Python + MCP + x402 + AP2 through identical scenarios (cross-path byte equivalence) |
| `security/` | Internal adversarial (hostile-AI) test suites over the agent-facing boundaries |
| `mobile/` | Native mobile app (Capacitor Android project + portable web payload, native production transport, bearer sign-in) — DEVELOPMENT status (see above) |
| `tests/vm/` | Real Kaspa VM covenant verification workspace (Rust; TxScriptEngine) |
| `deploy/` | Container build + staging/production compose examples + env templates |
| `docs/` | Protocol specs, architecture, threat model, invariants, hosted design, per-surface specs |

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
