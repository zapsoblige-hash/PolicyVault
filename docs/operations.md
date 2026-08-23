# PolicyVault Operations Runbook

## Environment

- Node: `kaspad` 2.0.1+, synced, **`--utxoindex`**. Default JSON wRPC
  listeners: testnet-10 `ws://127.0.0.1:18210`, mainnet
  `ws://127.0.0.1:18110` (Borsh listeners 17210/17110 — PolicyVault
  speaks **JSON** wRPC).
- Config: `sdk/src/config.js`. Overridable via `KASPA_NETWORK_ID`,
  `KASPA_RPC_URL`, and `POLICYVAULT_API_PORT`. Mainnet requires
  `POLICYVAULT_ALLOW_MAINNET=true` **and** an explicit `allowMainnet`
  override (the server derives it from the same env flag) **and** an
  explicit `KASPA_RPC_URL` — see `docs/deployment.md`.
- Data roots live inside the checkout and are per-network, network-stamped
  (`.pv-network`): `data/` (testnet-10) and `data-mainnet/` (mainnet). A
  process configured for one network refuses a root stamped for another.

## Start / stop

```bash
node server/src/server.js          # http://127.0.0.1:3080
# stop: Ctrl-C (or kill the pid)
```

Startup prints a posture report (network, data root, dev-signer /
test-hook / legacy-create status, mainnet-broadcast status, donation
configuration) and refuses to start on mainnet with any development or
test hook enabled.

## Health & connectivity

```bash
curl -s http://127.0.0.1:3080/api/v1/health
curl -s http://127.0.0.1:3080/api/v1/network/status   # networkId, isSynced, hasUtxoIndex, DAA
```

The SDK's `connectVerified` refuses to operate unless the node reports the
configured network, `isSynced: true`, and `hasUtxoIndex: true`.

## Inspect vault / request state

```bash
curl -s http://127.0.0.1:3080/api/v1/vaults
curl -s http://127.0.0.1:3080/api/v1/vaults/<vaultId>/status   # + chainConfirmed
curl -s http://127.0.0.1:3080/api/v1/vaults/<vaultId>/audit
```

On disk (per-network data root): `vaults/<id>/manifest.json`,
`claims/transition/*`, `claims/submission/*`, `receipts/*`,
`audit/events.log`.

## Reconcile a stuck submission (crash recovery)

If a process died after broadcasting but before advancing a manifest, run
Verify state — the dashboard button, or:

```bash
curl -s -X POST http://127.0.0.1:3080/api/v1/vaults/<vaultId>/reconcile \
  -H 'Content-Type: application/json' -d '{}'
```

Reconciliation never broadcasts; it advances local state only on exact
chain proof, releases stale claims only after proving the predecessor
still live and the expected effect absent, and fails closed to
`TERMINATED_UNKNOWN` when a consumed outpoint has no verifiable successor.
Never hand-edit or delete claim files.

## Backups & restore

Back up the entire per-network data root. To restore: stop the server,
copy the root back (including `.pv-network`), start, then run Verify
state on each active vault — reconciliation re-proves live state against
the chain and fails closed on divergence. Restoring an old backup cannot
forge chain state: manifests advance only behind exact chain proof. The
backup includes `orgs/` (organization metadata) — losing it loses business
grouping only, never funds.

## Recover after a backend crash

The backend holds no funds-critical in-memory state; restart it. Any
in-flight transitions are recovered by reconcile (above), which reads the
durable claims.

## Rotate application secrets

There are no PolicyVault-held signing secrets to rotate (non-custodial).
Local test keys (used only by the optional testnet verification drivers)
live under `keys/` (gitignored); regenerate by deleting the keyring file —
the next driver run recreates it.

## Deployment rollback

Everything is versioned (covenant, state format, requests, manifests) and
unknown versions fail closed. Roll back by redeploying the prior tagged
source; never let a rollback silently change the network.

## Do NOT

- log private keys or seed phrases;
- infer success from a disappeared UTXO;
- switch to mainnet or a public node silently;
- hand-edit manifests or claims;
- weaken funds-safety checks to satisfy a failing test — classify the
  failure first.
