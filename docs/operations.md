# PolicyVault Operations Runbook

## Environment

- Node: `kaspad` 2.0.1, **testnet-10**, `--utxoindex`, JSON wRPC
  `ws://127.0.0.1:18210`, Borsh wRPC `ws://127.0.0.1:17210`.
- Config: `sdk/src/config.js`. Overridable via `KASPA_NETWORK_ID`,
  `KASPA_RPC_URL`, `POLICYVAULT_API_PORT`, and `dataRoot`. Mainnet requires
  `POLICYVAULT_ALLOW_MAINNET=true` **and** an explicit `allowMainnet`
  override **and** an explicit `KASPA_RPC_URL` (Gate R granted 2026-08-22;
  operational deployment procedure: `docs/production-release.md` §8). A
  mainnet node needs kaspad 2.0.1+, synced, `--utxoindex` (mainnet JSON
  wRPC default port 18110; Borsh is 17110 — PolicyVault speaks JSON).

## Start / stop

```bash
# Backend + dashboard
cd server && node src/server.js          # http://127.0.0.1:3080
# stop: Ctrl-C (or kill the pid)
```

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

On disk (dataRoot, default `~/policyvault/data`):
`vaults/<id>/manifest.json`, `claims/transition/*`, `claims/submission/*`,
`receipts/*`, `audit/events.log`, `build/<stateId>/`.

## Reconcile a stuck submission (crash recovery)

If a process died after broadcasting but before advancing a manifest, run
reconcile-only. It never broadcasts; it advances local state only on chain
proof, and fails closed to `TERMINATED_UNKNOWN` when a consumed outpoint has
no verifiable successor:

```js
const { reconcileVault } = require("./sdk/src/reconcile");
await reconcileVault(config, vaultId); // {status: CONSISTENT | ADVANCED | UNKNOWN}
```

`tools/testnet-crash-recovery.js` demonstrates the full crash-after-broadcast
→ reconcile → RECOVERED flow.

## Backups & restore

Back up the entire `dataRoot`. It is self-describing: every manifest carries
the exact policy + state and is re-derivable/re-compilable via
`data/build/<stateId>/`. To restore, copy `dataRoot` back; the SDK re-reads
manifests and re-verifies live outpoints against the node. The backup set
includes `data/orgs/` (organization metadata + vault assignments) — losing
it loses business grouping/member records only, never funds: chain state
and vault manifests remain authoritative and vaults degrade to
"Unassigned".

## Recover after a backend crash

The backend holds no funds-critical in-memory state; restart it. Any in-flight
transitions are recovered by reconcile (above), which reads the durable claims.

## Rotate application secrets

There are no PolicyVault-held signing secrets to rotate (non-custodial). Test
keys live under `keys/` (gitignored); regenerate by deleting the keyring file
and re-running a tool, which recreates it.

## Deployment rollback

The covenant is versioned (`policyvault-0.1-beta`); unknown versions fail
closed. Roll back by pointing `config.contractSource` / `contractVersion` at
the prior artifact. Never let a rollback silently change the network.

## Do NOT

- log private keys or seed phrases;
- infer success from a disappeared UTXO;
- switch to mainnet or a public node silently;
- weaken funds-safety checks to satisfy a failing test — classify the failure
  first (CLAUDE.md, mission §69).

## Production operations addendum (Checkpoint I)

- Startup posture report: the server prints network, data root, dev-signer /
  test-hook / legacy-create status, mainnet-broadcast status, and donation
  configuration at listen time; a mainnet process refuses to start with any
  development hook enabled, and every process refuses a data root stamped
  for another network (`.pv-network`).
- Backup/restore: copy the whole per-network data root; restore; run Verify
  state per active vault. Full procedure: `docs/production-release.md` §6
  (restoration exercised 2026-08-22).
