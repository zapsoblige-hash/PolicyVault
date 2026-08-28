# Hosted Deployment: Containers, Startup, Staging Topology (Phase E)

**Status: IMPLEMENTED + STAGING-PROVEN on TESTNET-10 (Hosted Web
Architecture + Security checkpoint, Phase E, 2026-08-24). NOTHING here is
production: hosted production deployment remains a separate owner gate
("Authorize PolicyVault hosted production deployment."), production DNS
(`app.policy-vault.org`) is untouched, and hosted mainnet is impossible
in the staging configuration by construction.** Companion documents:
`docs/hosted-architecture.md` (topology/provider decisions),
`docs/hosted-persistence.md` (Phase C), `docs/hosted-request-protection.md`
(Phase D), `docs/hosted-backup-restore.md` (Phase E DR exercise),
`docs/hosted-staging-evidence.md` (measured staging results).

## 1. Deployment-posture configuration (Phase E additions)

All optional, all validated fail-closed in `sdk/src/config.js`; defaults
preserve the released self-hosted behavior exactly.

| Config | Env | Default | Rule |
|---|---|---|---|
| `bindAddress` | `POLICYVAULT_BIND_ADDRESS` | `127.0.0.1` | IP literal ONLY (never a hostname — DNS must not decide where the server listens). Non-loopback binding is an explicit operator act for container namespaces and requires an enclosing private network/firewall (the compose stack publishes NO ports). |
| `buildId` | `POLICYVAULT_BUILD_ID` | none | `[A-Za-z0-9._-]{1,64}`. Non-secret deployment identity (git short SHA) surfaced by `/health` and `/health/ready` — operators can prove WHICH build serves (stale-deployment protection, threat model "stale deployment" row). Never derived from requests. |
| `dataRoot` | `POLICYVAULT_DATA_ROOT` | repo `data/` (`data-mainnet/` on mainnet) | Absolute path only. In postgres mode the data root holds ONLY the `.pv-network` stamp and the derivable compiled-artifact cache — durable state lives in PostgreSQL. |
| `stagingBanner` | `POLICYVAULT_STAGING_BANNER=1` | off | `/health` reports `staging:true` and the UI banner renders "TESTNET-10 STAGING — NON-PRODUCTION". REFUSED on mainnet at config time (staging is testnet-only; a mainnet process can never wear a staging label). |

## 2. Startup order (fail closed — no HTTP before proof)

```
configuration validation            loadConfig() — every unlock/refusal
        ↓
durable backend OPEN                postgres: connect + schema EXACTLY
                                    current + write-once network stamp
                                    (openPgStore; the server NEVER
                                    auto-migrates)
        ↓
startup posture validation          validateStartup() — data-root stamp,
                                    mainnet dev-hook refusals, posture
                                    report (no secrets)
        ↓
listen                              config.bindAddress only
```

Any failure exits non-zero without ever accepting a request (proven by
child-process tests: unreachable DB, unmigrated schema, mainnet without
the dual unlock — `sdk/test/hosted-deployment.test.js`). The old
behavior (listen first, fail per-request) is proven load-bearing by
sabotage: with the DB-open step neutralized, a hosted server happily
listens with a dead database (`hosted-deployment-sabotage.test.js` S1).

**Migrations are an explicit deployment STEP, never a side effect:**
`node server/src/migrate.js` (standalone; fixed in Phase E — it
previously could not resolve `pg` outside the sdk package and died with
MODULE_NOT_FOUND) or `docker compose … run --rm migrate`. The advisory
lock + per-file checksums make concurrent migrators serialize (two
simultaneous child migrators proven safe); the serving container refuses
to start until the schema is exactly current, so a fleet of replicas can
never race schema initialization — replicas only ever VERIFY.

## 3. Health surfaces

- **`GET /api/v1/health` — LIVENESS.** Cheap, no dependency dials.
  Reports api version, network, authMode, buildId, staging flag. An
  orchestrator must not kill a process because a dependency blinked.
- **`GET /api/v1/health/ready` — READINESS.** postgres mode proves, in
  order: store open → database answering (`SELECT 1`) → schema exactly
  current → network stamp matches; json mode proves the data-root stamp.
  Failure: 503 `{ready:false, reason}` with a coarse machine-readable
  reason (`STORE_NOT_OPEN`, `DATABASE_UNREACHABLE`, `SCHEMA_NOT_CURRENT`,
  `NETWORK_STAMP_MISMATCH`, `DATA_ROOT_NOT_STAMPED`) — never internals,
  never credentials. The container HEALTHCHECK probes readiness.
- The trusted kaspad tier is deliberately NOT in readiness: a node
  outage is an availability event surfaced by `/network/status`;
  restarting the app cannot fix it and must not be triggered by it.
- Readiness truthfulness is sabotage-proven (S2: skipping the postgres
  branch makes readiness lie while the DB is down — RED, restored).

## 4. Container artifact (`deploy/Dockerfile`)

Multi-stage, build context = repo root filtered by a **DEFAULT-DENY
`.dockerignore`**: everything is excluded, then only the runtime paths
are re-included (sdk/src+lockfile, server/src+migrations, web,
contracts minus experiments, deploy/vendor). Private material (.git,
continuation notes, owner directives, docs.zip, data roots, keys,
wallets, .env, backups) never reaches the Docker daemon at all — it
cannot exist in any layer of any stage.

- Base: pinned `ubuntu:26.04` (glibc 2.43 — matches the host toolchain
  that built the staged binaries; resolved digest recorded in the
  staging evidence).
- Node.js v20.20.2 installed from the OFFICIAL release tarball, verified
  against the official `SHASUMS256.txt` inside the build — the exact
  runtime the release gate ran.
- Dependencies: `npm ci --omit=dev` against the committed lockfile in an
  isolated stage; no toolchains in the final image; `npm audit` gate
  unchanged (0 vulnerabilities).
- **Staged authoritative artifacts** (`tools/stage-vendor.sh`, SHA256
  manifest `deploy/vendor/SHA256SUMS.txt`, recorded in evidence): the
  pinned kaspa-wasm module, `silverc`, and `pv_call_encoder` /
  `pv_vm_preflight` / `pv_tx_probe` — the EXACT binaries the release
  gate verified on this machine. The container runs the verified bytes;
  it does not rebuild them. (A from-source containerized toolchain build
  is a recorded future improvement, needing the pinned silverscript +
  rusty-kaspa trees and a Rust stage.)
- Runtime user: `pv` (uid 10001, nologin). Application code, vendor
  binaries, and node_modules are ROOT-owned and read-only to `pv` — a
  compromised app cannot rewrite its own code, the covenant compiler, or
  the VM preflight binary. The ONLY writable path is the data root
  (mode 700, pv-owned), which in postgres mode holds only the network
  stamp + regenerable compiled-artifact cache.
- `HEALTHCHECK` = the readiness probe (above). `EXPOSE 3080` is
  informational; the compose stack publishes NOTHING.
- Image privacy: `tools/image-privacy-scan.sh <image>` scans EVERY layer
  blob of `docker save` output (paths AND raw bytes) for private-repo
  material, key material, and canary markers — not just the merged
  filesystem, so nothing can hide in an intermediate layer. A canary
  sabotage run (planting a fake secret in the context) must turn the
  scan RED. The scanner carries a NARROW, classified benign-class
  filter (public CA trust store, the `usr/lib/ssl/cert.pem` bundle
  symlink, the empty `var/backups/` entry, node_modules module dirs
  named `keys/`) discovered on the first REAL image scan (Phase E-R);
  `--classify-paths` exposes the exact filter for the docker-free
  regression suite `sdk/test/image-scan-classify.test.js`.
- **EXECUTED (Phase E-R, 2026-08-24/25 — `docs/hosted-phase-e-r-evidence.md`):**
  the image was actually built from `88567e0` on Docker Engine 29.1.3
  (image ID `sha256:446eb5db…`, base
  `ubuntu:26.04@sha256:2260313b…`, 204,202,007 bytes, 22 layers, USER
  pv) and the every-layer scan ran **CLEAN (28 blobs)**. Runbook step 1
  is no longer a never-executed instruction; rebuilds must repeat it.

## 5. Staging stack (`deploy/docker-compose.staging.yml`) — TESTNET-10 ONLY

```
internet ── Cloudflare edge (TLS, DDoS, quick-tunnel hostname)
                 │  outbound-only authenticated tunnel
            cloudflared container ──► app:3080     (compose network only)
                                       │
                                       ├─► postgres:5432   (compose network only)
                                       └─► host-kaspad:18210 (host-side private
                                            forwarder → 127.0.0.1:18210 JSON wRPC)
```

- **NO service publishes a host port.** Ingress is exclusively the
  Cloudflare Tunnel; PostgreSQL and the app are reachable only on the
  compose-private network. Port 3080 is never internet-reachable.
- The app container: non-root, `read_only: true` rootfs, tmpfs `/tmp`
  and tmpfs data root (both size-bounded), `mem_limit`/`pids_limit`/
  `cpus`, bounded json-file log rotation, `restart: unless-stopped`.
  These are DEPLOYMENT-level bounds layered over the Phase D
  application-level protections (rate limits, semaphores, deadlines,
  quotas) — neither replaces the other.
- postgres: pinned image, durable named volume (`pv-staging-pgdata`),
  bounded logs/memory/pids, `pg_isready` healthcheck. Compose-network
  PG uses the explicit no-TLS override (permitted on testnet only) — a
  documented staging-only concession; production is DigitalOcean Managed
  PG with TLS and a private endpoint.
- cloudflared: pinned image, **Quick Tunnel** (`--url http://app:3080`):
  outbound-only, no account, no credential, random
  `*.trycloudflare.com` hostname — unmistakably non-production, nothing
  to leak, and production DNS is untouched by construction. The assigned
  URL becomes `POLICYVAULT_APP_ORIGIN` (exact-match Origin gate + Host
  allowlist + Secure/`__Secure-` cookies over the edge TLS).
- **kaspad staging transport** (`tools/staging-kaspad-proxy.js`): the
  operator's testnet node correctly binds its JSON wRPC to loopback
  only; containers cannot reach host loopback, so a host-side forwarder
  listens ON THE DOCKER BRIDGE GATEWAY ADDRESS ONLY (refuses to bind
  any non-private IP by code) and forwards to 127.0.0.1:18210. This is
  a documented BOOTSTRAP/STAGING topology — the production kaspad tier
  remains a dedicated VPC host with provider firewalling (architecture
  §5). The RPC ports (18110/18210/17110/17210) are never
  internet-reachable in either shape.
- Secrets: `deploy/staging.env` (gitignored; template
  `deploy/staging.env.example` carries placeholders only). Staging
  credentials are staging-only and rotated/destroyed per the evidence
  doc. There are NO wallet-key secrets in any deployment component, by
  design — deployment automation can start services, migrate, route,
  back up, restore, and health-check; it can never authorize a covenant
  transition.

## 6. Deploy / rollback identity

The image carries `POLICYVAULT_BUILD_ID` (git short SHA) baked at build
time and surfaced by `/health` — the running artifact is provably the
reviewed commit, and `latest`-style mutable-tag deploys are never the
only identity. Rolling BACK between images is permitted only within the
same schema version: the startup schema gate refuses an image whose
migration set is older than the database (fail closed, proven —
`schema version N is newer than this build`), so a rollback across a
migration is impossible to do silently: it requires an explicit
database restore or a forward fix. There is deliberately no "one-click
rollback" claim.

## 7. What Phase E staging is NOT

- NOT production; NOT `app.policy-vault.org` (no DNS record was created
  or modified); NOT mainnet (the dual unlock is absent and the staging
  banner is mainnet-refused; a deployment-level negative test proves a
  mainnet env refuses to boot).
- NOT the Phase G human acceptance (automated Schnorr harness identities
  only) and NOT the Phase F full hostile multi-user review.
- The self-hosted released product is unchanged: default bind stays
  loopback, JSON backend stays default, no new required configuration.
