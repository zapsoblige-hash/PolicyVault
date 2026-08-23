# PolicyVault Deployment

## Environments

Three explicit, non-overlapping configurations. A network is never silently
promoted; mainnet requires deliberate opt-in at multiple layers.

| Env | networkId | rpcUrl | Broadcasting |
|---|---|---|---|
| development | testnet-10 | ws://127.0.0.1:18210 | allowed |
| testnet | testnet-10 | operator-provided | allowed |
| mainnet | mainnet | operator-provided (REQUIRED, no default) | allowed under the dual-flag opt-in (below) |

Set via env: `KASPA_NETWORK_ID`, `KASPA_RPC_URL`, `POLICYVAULT_API_PORT`,
`dataRoot`. Unknown `KASPA_NETWORK_ID` values fail closed at
`config.loadConfig`.

kaspad's default wRPC listeners: mainnet JSON `18110` / Borsh `17110`;
testnet-10 JSON `18210` / Borsh `17210`. PolicyVault's client speaks
**JSON wRPC** — point `KASPA_RPC_URL` at the JSON listener.

## Mainnet dual-flag opt-in

`config.loadConfig` throws for `networkId: mainnet` unless BOTH:

1. `POLICYVAULT_ALLOW_MAINNET=true` in the environment, and
2. an explicit `allowMainnet: true` override is passed in code (the server
   entrypoint supplies it from the same env flag, so the operator's dual
   act is `KASPA_NETWORK_ID=mainnet` + `POLICYVAULT_ALLOW_MAINNET=true`),

plus an **explicit `KASPA_RPC_URL`** (a mainnet process never inherits the
testnet default endpoint) against the empty `data-mainnet` root.

Under that configuration the transaction pipeline requires
config == request == manifest == node network agreement at build,
preflight, submit, and reconcile; unknown networks fail closed; and
startup refuses to run on mainnet with the dev signer, test hooks, or
legacy vault creation enabled. Ramp up deliberately: a tiny-value smoke
vault first, then strictly value-capped vault policies, then incremental
increases.

## Backend deployment (production-oriented sketch)

- Run `server/src/server.js` behind a reverse proxy (TLS terminates at the
  proxy). The API sets `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, and a strict `Content-Security-Policy`; the static
  dashboard uses a scoped CSP allowing its own inline style only.
- Process supervision: run under a supervisor (systemd/pm2) that restarts on
  exit. The backend is stateless beyond `dataRoot`; restart is safe.
- Persist and back up `dataRoot` on durable storage (see
  `docs/operations.md`).
- The backend holds no keys; it cannot move funds and is not the security
  boundary.

The supported first-release deployment is **local / self-hosted,
single-operator, loopback**: the server binds `127.0.0.1` and serves the
UI + API from one origin. An internet-hosted multi-user deployment has not
been reviewed and is not supported by this release — do not expose
`127.0.0.1:3080` to the public internet.

## Frontend

The dashboard in `web/` is static and self-contained (no external hosts). It
is served by the backend at `/`. For a standalone deploy, serve `web/` from
any static host and point it at the API origin (adjust the `API` constant).

## Dependency posture

- SDK runtime dependency: `websocket` only. Backend: none beyond Node stdlib.
- The Kaspa WASM SDK and `silverc` / `pv_call_encoder` are local toolchain
  binaries from the pinned reference repos, not npm packages.
- Pin the node version (`kaspad` 2.0.1+) and the SilverScript/rusty-kaspa git
  tag (`v2.0.1`) used to build the encoder and VM suite.

## Release verification behind this build

This release shipped only after, in order: real-VM covenant proof of every
entrypoint (positive + adversarial matrices), production-byte encoder
integration, hostile SDK/API/browser review with sabotage-sensitivity
checks, crash/concurrency/reconciliation matrices, full live testnet-10
lifecycles with real KasWare signing (including authorized testnet
negative-validation transactions constructed independently of the
application, verifying that consensus rejects policy-invalid transactions
even when correctly signed by the designated agent), backup/restore
rehearsal, and a limited real-value mainnet smoke test. An independent
professional security review has **not** yet occurred and is never
claimed; begin with conservative values.
