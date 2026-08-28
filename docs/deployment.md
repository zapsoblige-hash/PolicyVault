# PolicyVault Deployment

## Environments

Three explicit, non-overlapping configurations. A network is never silently
promoted; mainnet requires deliberate opt-in at multiple layers.

| Env | networkId | rpcUrl | Broadcasting |
|---|---|---|---|
| development | testnet-10 | ws://127.0.0.1:18210 | allowed |
| testnet | testnet-10 | operator-provided | allowed |
| mainnet | mainnet | operator-provided (REQUIRED, no default) | allowed under the dual-flag unlock (Gate R granted 2026-08-22; see below) |

Set via env: `KASPA_NETWORK_ID`, `KASPA_RPC_URL`, `POLICYVAULT_API_PORT`,
`dataRoot`. Unknown `KASPA_NETWORK_ID` values fail closed at
`config.loadConfig`.

## Mainnet dual-flag unlock (Gate R granted 2026-08-22)

`config.loadConfig` throws for `networkId: mainnet` unless BOTH:

1. `POLICYVAULT_ALLOW_MAINNET=true` in the environment, and
2. an explicit `allowMainnet: true` override is passed in code (the server
   entrypoint supplies it from the same env flag, so the operator's dual
   act is `KASPA_NETWORK_ID=mainnet` + `POLICYVAULT_ALLOW_MAINNET=true`),

plus an **explicit `KASPA_RPC_URL`** (a mainnet process never inherits the
testnet default endpoint) against the empty `data-mainnet` root.

The owner's Gate R authorization ("Authorize Gate R. Enable PolicyVault
mainnet production release.", 2026-08-22) made mainnet OPERATIONAL under
exactly that configuration: the pipeline requires config==request==
manifest==node network agreement and refuses dev signer / test hooks /
legacy create on mainnet at startup. Deployment procedure + ramp-up:
`docs/production-release.md` §8 (tiny-value smoke test first; strict
value-capped vault policies; incremental increases — mission §64).

## Backend deployment (production-oriented sketch)

- Run `server/src/server.js` behind a reverse proxy (TLS terminates at the
  proxy). The API sets `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, and a strict `Content-Security-Policy`; the static
  dashboard uses a scoped CSP allowing its own inline script/style only.
- Process supervision: run under a supervisor (systemd/pm2) that restarts on
  exit. The backend is stateless beyond `dataRoot`; restart is safe.
- Persist and back up `dataRoot` on durable storage (see
  `docs/operations.md`).
- The backend holds no keys and exposes only read/status/audit routes; it
  cannot move funds.

## Frontend

The dashboard in `web/` is static and self-contained (no external hosts). It
is served by the backend at `/`. For a standalone deploy, serve `web/` from
any static host and point it at the API origin (adjust the `API` constant).

## Dependency posture

- SDK runtime dependency: `websocket` only. Backend: none beyond Node stdlib.
- The Kaspa WASM SDK and `silverc` / `pv_call_encoder` are local toolchain
  binaries from the pinned reference repos, not npm packages.
- Pin the node version (`kaspad` 2.0.1) and the SilverScript/rusty-kaspa git
  tag (`v2.0.1`) used to build the encoder and VM suite.

## Mainnet release gates (must all pass first)

The authoritative gate record is `docs/production-completion-checklist.md`
(Master Production Completion Directive, 2026-08-16): mandatory gates A–R,
including complete real-KasWare manual lifecycle, organization UX,
scalable recipient authorization, v0.3 covenant multisig/approvals,
complete VM negative-validation matrix, complete SDK/API/browser tests,
property/fuzz testing, crash/concurrency/reconciliation hardening,
production deployment/containerization, monitoring/alerting,
backup/restore rehearsal, clean fresh-environment testnet deployment
rehearsal, security-critical code freeze, and separate explicit owner
authorization before any mainnet broadcasting. An **independent
professional security review** is PLANNED and POST-LAUNCH ACCEPTABLE
(owner policy update, 2026-08-17) — important but no longer a pre-mainnet
blocker; it must never be falsely claimed as done.

Underlying suites: covenant VM PASS · negative-validation VM matrix PASS ·
SDK PASS · API smoke PASS · crash/recovery PASS · full testnet lifecycle
PASS · authorized testnet negative-validation demonstration PASS
(negative-validation transactions constructed independently of the
PolicyVault application, verifying that consensus rejects policy-invalid
transactions even when correctly signed by the designated delegate) ·
deployment rehearsal PASS · security docs complete · no open P0/P1
blockers.

**Review/release status (owner policy update, 2026-08-17):** external
professional review is planned and post-launch acceptable, not a
pre-mainnet blocker; audit/external-review status is never fabricated
(mission §63). Explicit owner mainnet authorization (gate R) remains a
hard human gate. Deployment packaging/containerization (Phase 6),
monitoring (Phase 7), backup/restore rehearsal (Phase 8), and the
fresh-environment rehearsal (Phase 9) are OPEN items tracked in the
checklist.

## Production release (Checkpoint I)

The authoritative production posture — supported deployment model
(local/self-hosted loopback), HTTP threat model, per-network data roots +
cross-network refusal, dev/test-hook isolation, donation configuration,
backup/recovery, mainnet node requirements, and the Gate-R mainnet release
procedure — is `docs/production-release.md`. This file's environment/lock
description remains accurate; the production doc supersedes it where more
specific.
