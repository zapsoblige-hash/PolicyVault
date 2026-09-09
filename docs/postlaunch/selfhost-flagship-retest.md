# Self-hosting flagship re-test (Track 10)

**Status: INTEGRATION-VERIFIED locally for every headlessly-testable step.**
Real Docker (rootless 29.1.3), real PostgreSQL 16 (bundled compose
service), the operator's real local testnet-10 kaspad (READ-ONLY, via the
documented `tools/staging-kaspad-proxy.js` host-side forwarder — never
stopped or restarted), and the real `tools/prod-acceptance.js` harness
(37/37, including a real Schnorr sign-in with a throwaway generated test
keypair). Full interactive KasWare browser sign-in is
**NOT-TESTED-HEADLESS** by design (needs a real browser + extension +
human wallet interaction) — noted wherever relevant below.

Method: acted as an outside operator with no PolicyVault development
history, following only `docs/selfhost-quickstart.md` and
`deploy/selfhost.sh`'s own `--help`-style usage banner, against a **clean
`git archive HEAD` copy** of the checkout (no `.git`, no `node_modules`,
no dev scratch) — exactly the tree shape a self-hoster gets. All work
happened in scratch directories under `/tmp`; nothing was written outside
this worktree. An automated, idempotent, self-cleaning driver for this
exact flow now lives at `tools/selfhost-acceptance.sh` (see §5) and was
run to completion after every fix below landed, with clean final state
(`docker ps/volume/network/images` show nothing left over).

## 1. Step matrix

| Step | Result | Evidence |
|---|---|---|
| Clean-copy extraction (`git archive HEAD \| tar -x`) | PASS | no `.git`, no `node_modules`; only the tracked tree (see §4 on the tracked `data/` evidence files, which is not a self-hosting defect) |
| Dependency staging — `tools/stage-vendor.sh` | **FAIL → FIXED** | Two real bugs found and fixed; see §2.1–§2.2 |
| Node connectivity: wrong/absent node | PASS | `/api/v1/network/status` never fabricates success with no reachable node; see §3.1 for a related (deferred) responsiveness finding |
| Node connectivity: real node via the documented forwarder | PASS | `networkId=testnet-10 isSynced=true hasUtxoIndex=true`, live DAA score matched the real chain |
| PostgreSQL (bundled compose service) | PASS | healthcheck green, `pg_isready`, non-published port, compose-private network only |
| Migration (`server/src/migrate.js` / `selfhost.sh up`'s one-shot `migrate` service) | PASS | `migrate: schema current (9 migrations known)`, advisory-locked, idempotent on re-run |
| App startup | PASS | posture banner correct (dev-signer/test-hooks/legacy-create disabled, mainnet disabled, hosted auth enabled with the documented insecure-cookie override only on loopback HTTP) |
| `/health` and `/health/ready` | PASS | `ok:true`, `ready:true`, exact `buildId` match |
| Network verification (testnet-10 identity; mainnet dual-unlock) | PASS | `check`'s 13/13 posture checks green; mainnet path independently code-reviewed (`sdk/src/config.js` dual-flag + explicit-RPC-URL + TLS-required-on-mainnet gates — all fail closed, not separately re-exercised live since it needs real mainnet infra out of this track's scope) |
| Wallet auth — challenge endpoint | PASS (headless-testable slice) | Endpoint reachable, validates input, rate-limited under load; full sign-in proven via `prod-acceptance.js`'s real-Schnorr-with-test-keypair flow (37/37) |
| Wallet auth — real KasWare browser sign-in | NOT-TESTABLE-HEADLESS | Requires a real browser + KasWare extension + human wallet interaction |
| Vault discovery (read-only against the node) | PASS (code-path proof) | The identical authenticated tenant-scoped read path is proven by the acceptance suite's org create/list/isolation checks (`GET /vaults` shares this exact code path); a real chain-scanned vault listing needs an actual on-chain vault, which needs a wallet-signed creation — out of headless scope |
| Backup (`selfhost.sh backup`) | PASS | `pg_dump -Fc`, mode 600, correct byte-size delta on a real data change |
| Restore into a fresh, isolated PostgreSQL DB | PASS | `pg_restore` into a brand-new `createdb`, row counts and network stamp verified exactly at the backup point (differential test: B1=1 org, B2=2 orgs, each restore reproduced exactly) |
| Restore in place (documented Day-2 op, `selfhost.sh restore FILE`) | PASS | explicit `RESTORE` confirmation, app stopped/restored/restarted, data reverted correctly, `ready:true` after |
| Update (rebuild image from a changed tree, restart, data intact) | **FAIL → FIXED** | `deploy/selfhost.sh upgrade` always refused ("nothing to upgrade to") on a git-less checkout, even after a real source edit; see §2.3 |
| Rollback (previous image tag, data intact) | **FAIL → FIXED** | Served `buildId` did not match the actually-running (rolled-back) image after `rollback`; see §2.4 |
| Diagnostics | PASS | `selfhost.sh status/logs/check/acceptance`; `/api/v1/metrics` correctly requires sign-in (hosted-auth mode, matching `docs/postlaunch/operational-observability.md`) |
| Log redaction | PASS | grepped app + postgres container logs for seed/mnemonic/private-key/password/PEM-block patterns and the actual generated PG password and a deliberately-wrong probe password — zero hits |
| Failure messages — missing env | PASS | `no deploy/selfhost.env — run: bash deploy/selfhost.sh init` |
| Failure messages — bad DB URL/credential | PASS | app crash-loops with `PolicyVault startup failed (fail closed): password authentication failed for user "pvselfhost"` — no data served, clear cause |
| Failure messages — bad node URL | PASS (with a caveat) | Never fabricates success; see §3.1 for a deferred responsiveness finding (the failure is eventually silent-drop rather than a fast clear error) |
| Shutdown/restart (`down` / `up`) | PASS | data volume kept across `down`; `up` recreates network+containers, migration re-runs idempotently, data intact |
| Host reboot simulation (`docker restart` of the whole stack) | PASS | both containers return healthy, readiness returns within seconds, data intact |
| Uninstall (`destroy`) | PASS | explicit `DESTROY` confirmation; volume, network, containers, and `selfhost.env`/`.selfhost-state` removed; images intentionally kept (documented) |
| Hidden dependency scan | PASS | see §4 |
| Hardening comparison vs hosted | PASS — no gap | see §6 |

**Fixed:** 3 genuine bugs (2 script/UX, 1 correctness-of-observability).
**Deferred (not self-host-specific, broader blast radius, out of this
track's scope):** 1 finding, §3.1.

## 2. Fixes

### 2.1 `tools/stage-vendor.sh` — spurious failure when `deploy/vendor/dist/` doesn't exist yet

`find bin kaspa dist -type f 2>/dev/null | sort | xargs sha256sum >
SHA256SUMS.txt` ran under `set -o pipefail`. `find` exits non-zero when
one of its listed starting paths doesn't exist (`dist/`, which is
populated by a *separate* manual Node-dist pre-fetch step and is normally
absent on a first run) — even though the redirected manifest output was
already complete and correct. `pipefail` propagated that non-zero status
through the pipeline, and `set -e` then aborted the whole script
immediately after successfully staging `kaspa/` and `bin/`. Concretely:
**every first-time run of `tools/stage-vendor.sh` reported failure**, and
because `deploy/selfhost.sh up` runs this script and treats any nonzero
exit as fatal (`|| die "stage-vendor failed — ..."`), a fresh self-hoster
following the docs verbatim could never get past `up`.

Fix: only pass *existing* top-level directories to `find`. Verified both
ways: with `dist/` absent (the common case) and present (regression
check) — both now report `staged. manifest:` and exit 0.

### 2.2 `tools/stage-vendor.sh` / `docs/selfhost-quickstart.md` — undocumented hard prerequisite

A fresh checkout has no `tests/vm/target/debug/` (gitignored Rust build
output) and no `deploy/vendor/dist/` (pre-fetched Node tarball).
Reproduced exactly what an outsider hits: `cp: cannot stat
'.../pv_call_encoder': No such file or directory`, with **no doc anywhere
in the repo** saying to run `cd tests/vm && cargo build` first (the
top-level `README.md`'s dev-path build section documents this for the
*local dev* flow, not the containerized self-hosting flow, and
`docs/selfhost-quickstart.md` didn't mention it at all). Similarly, `up`'s
own error message for a missing Node dist ("pre-fetch it per the
stage-vendor.sh header") pointed at a header that never actually said
*how* — verified against the real official `nodejs.org` release (fetched
and SHA256-verified `node-v20.20.2-linux-x64.tar.xz` against the real
`https://nodejs.org/dist/v20.20.2/SHASUMS256.txt` to confirm the exact
commands work).

Fix:
- `tools/stage-vendor.sh` now checks each of the three external
  prerequisites (rusty-kaspa WASM module, `silverc`, the three `pv_*`
  binaries) individually and fails closed with an actionable message
  naming the exact missing path and the exact command to build it,
  instead of a raw `cp` error.
- `docs/selfhost-quickstart.md` Prerequisites now lists the Rust
  toolchain and the exact `cargo build` commands for both sibling repos
  and `tests/vm`.

### 2.3 `deploy/selfhost.sh` — `upgrade` permanently broken on a git-less checkout

`build_id` fell back to the **constant literal** `"selfhost"` whenever
`.git` metadata was absent — which is exactly the shape of a self-hosted
checkout obtained as a release tarball/zip (or, as tested here, a `git
archive` export — the project's own documented publication method,
`docs/product-policy.md`). Because `cmd_upgrade` refuses when the
computed new tag equals the current tag ("source tree is at the same
build — nothing to upgrade to"), and the constant fallback makes every
git-less build compute the *same* tag forever, **`bash deploy/selfhost.sh
upgrade` could never succeed for such an operator, even after a real,
verified source edit.** Reproduced directly: edited `server/src/server.js`,
ran `upgrade`, got the refusal with the source change sitting right there
uncommitted-but-present.

Fix: `build_id` now prefers the git short SHA when available
(unchanged behavior for git checkouts — verified byte-identical to the
prior behavior when `.git` is present) and, only when git metadata is
absent, falls back to a **content hash** of the exact runtime source
paths (`core`, `sdk/src`, `sdk/package.json`, `sdk/package-lock.json`,
`server/src`, `server/migrations`, `server/package.json`, `web`,
`contracts`, `deploy/Dockerfile` — the same paths that end up in the
Docker build context) rather than a constant. The whole computation is
wrapped so any failure still degrades to the old literal `"selfhost"`
(never worse than before). Verified: a real source edit now changes the
computed id (`selfhost-selfhost` → `selfhost-c5fdfb62cf57`-shaped),
`upgrade` proceeds, rebuilds, and restarts with data intact.

### 2.4 `deploy/selfhost.sh` — `rollback` restored the wrong image tag but not the matching `buildId`

`POLICYVAULT_BUILD_ID` is a **runtime** value (`env_file:`) that overrides
whatever the image itself was baked with — that's by design, so
`/health`'s `buildId` reflects the *deployment's* declared identity. But
`cmd_rollback` only restored `PV_SELFHOST_APP_TAG` from the state file,
never `POLICYVAULT_BUILD_ID`. Reproduced directly: after an `upgrade`
followed by a `rollback`, the running container was genuinely back on the
old image (`docker inspect` confirmed the container's `Image` field and
`docker compose ps` both showed the old tag) — but `/api/v1/health`
reported the **new (upgraded)** build's id. This is exactly the
confusion `buildId` exists to prevent (the doc calls it "stale-deployment
protection" — "operators can prove WHICH build serves"): an operator
rolling back after a bad deploy, and using `buildId` to confirm the
rollback took effect, would be told they're still running the bad build
when they are not.

Fix: `cmd_upgrade` now records `PREVIOUS_BUILD_ID` alongside
`PREVIOUS_TAG` in `deploy/.selfhost-state`; `cmd_rollback` restores both
together (with a clear warning if an old-format state file only has
`PREVIOUS_TAG`, so a stale state file degrades to the previous behavior
rather than silently doing the wrong thing). Verified end to end: upgrade
→ rollback now serves the buildId that matches the actually-running
image.

## 3. Deferred (recorded, not fixed under this track)

### 3.1 `sdk/src/chain.js` `connectVerified` — slow, silent failure against an unreachable-but-routable RPC address

Reproduced by pointing the default self-host RPC URL (`ws://host-kaspad:
18210`, i.e. the Docker bridge gateway) at a port with **nothing
listening** (the normal state before the operator starts the documented
`tools/staging-kaspad-proxy.js` forwarder — a very plausible real
self-hosting mistake, not a contrived edge case). A raw TCP connect to
that same address from inside the app container refuses instantly
(`ECONNREFUSED` in ~7ms). But `GET /api/v1/network/status` did not return
any error to the client within 150s of wall-clock observation — the HTTP
layer's own `httpTimeouts.requestMs` (default 30000ms) eventually
force-destroys the socket with **no response body at all** (curl reports
`HTTP_STATUS:000`), and no structured log line for that request ever
appears. Once the forwarder was started, the *same still-pending*
request(s) connected immediately (the forwarder's log showed 4
simultaneous incoming connections the instant it started listening,
matching the `rpc` semaphore's `max: 4` — consistent with the underlying
`kaspa.RpcClient.connect({timeoutDuration: 15000})` retrying in the
background well past both its own stated 15s timeout and the app's 30s
HTTP timeout, rather than failing fast).

This is **not a self-hosting-specific regression** — `connectVerified` is
shared code used identically by the hosted deployment, `create-vault`,
`spend-vault`, `reconcile`, and every RPC-touching route, so a fix
belongs to a dedicated review of `sdk/src/chain.js` with its own test
suite (`sdk/test/`), not a narrow self-hosting pass. Recorded for that
review: (a) the operator-facing failure mode for "wrong/absent node URL"
is a silent connection drop after 30s rather than a fast, clear error
body; (b) the underlying RPC connect attempt does not appear to be
cancelled when the HTTP request times out, and repeatedly hitting a
black-holed RPC endpoint could degrade the `rpc` concurrency semaphore
(max 4, queue 16) for unrelated requests during that window — observed
recovering fully once the endpoint became reachable, so this is a
bounded availability/UX concern, not a demonstrated permanent DoS.
Suggested remediation for that future review: wrap `connectVerified`'s
`rpc.connect` in an explicit outer timeout (e.g. `Promise.race` /
`AbortController`) independent of the WASM client's own internal
behavior, and have `/network/status` return a distinguishable
`RPC_UNREACHABLE`-shaped JSON error within the existing HTTP timeout
budget instead of a silently destroyed socket.

## 4. Tracked `data/` evidence files (observation, not a defect)

The repository has real testnet-10 vault manifests/claims/receipts
tracked under `data/` (historical evidence from earlier development,
predating or bypassing the `data/` gitignore rule) — these appear in a
`git archive` clean copy too. They contain no private key material (no
custody exists in this design) and are excluded from the Docker build
context by `.dockerignore` (`**/data`), so they never reach the running
image. Noted for completeness per the hidden-dependency/privacy scan
scope of this track; not a self-hosting functional defect and out of
scope to prune here (a publication-readiness concern, already governed
by the project's separate publication-scan process in
`docs/product-policy.md`).

## 5. `tools/selfhost-acceptance.sh`

New automated, idempotent, self-cleaning acceptance driver. It:

- extracts a clean `git archive HEAD` copy into a scratch workdir (never
  touches this checkout's own `deploy/selfhost.env` or any real running
  stack);
- reuses an already-staged `deploy/vendor/` from the checkout it's run
  from (does not itself build the Rust VM toolchain or fetch the Node
  dist over the network — reported as `REQUIREMENT_NOT_AVAILABLE` and
  stops cleanly if that staging hasn't been done yet, pointing at
  `tools/stage-vendor.sh`);
- drives init → missing-env failure message → up → health/ready →
  node-absent fail-closed → node-present via the documented forwarder →
  `check` (13/13) → `acceptance` (37/37, real Schnorr sign-in) → auth
  challenge reachability → backup → restore-into-a-fresh-isolated-DB
  (row-count + network-stamp verification) → restore-in-place → bad-PG-
  credential fail-closed message → upgrade (content-hash buildId on a
  real source edit) → rollback (served buildId matches the rolled-back
  image) → log redaction → `docker restart` host-reboot simulation →
  hidden-dependency scan → destroy;
- prints a PASS/FAIL/SKIP matrix and a summary count, and exits non-zero
  if anything failed;
- names every container/volume/network/image it creates with a
  configurable prefix (`PV_ACCEPT_PREFIX`, default
  `pvselfhost-acceptance`; this track's runs used `pvselfhost-t10` per
  the worktree's cleanup convention) and removes all of them (plus its
  scratch workdir) in a `trap ... EXIT`, so a re-run — or an interrupted
  run — never leaves residue.

Run: `PV_ACCEPT_PREFIX=pvselfhost-t10 bash tools/selfhost-acceptance.sh`
(takes a real local kaspad on testnet-10 with `--utxoindex`; a Rust-built
`deploy/vendor/` staged once beforehand; Docker with the compose plugin).
Final run against the fixed, committed source: **22/22 steps PASS**
(1 SKIP category possible only if `deploy/vendor` isn't staged, which
short-circuits the run cleanly instead of failing).

The tool's own first real end-to-end run surfaced one bug in itself: the
image-cleanup step only matched `policyvault-app:<PREFIX>*`, but
`deploy/selfhost.sh upgrade` always retags to its own
`selfhost-<buildId>` scheme regardless of the prefix a run started with,
so the UPGRADE step's resulting image was left behind. Fixed by
snapshotting every `policyvault-app:*` tag before the run starts and
removing exactly the set difference at cleanup (never a naming-pattern
guess, and never touching an image that predates the run — e.g. a
concurrent session's). Verified clean: a full run now leaves zero
residual containers, volumes, networks, or images (checked directly
against `docker images/ps/volume ls` before and after).

## 6. Hardening comparison: self-hosted vs hosted production

| Control | `docker-compose.selfhost.yml` (`app`) | `docker-compose.prod.yml` (`app`) | Gap? |
|---|---|---|---|
| Non-root runtime user | `pv` (uid 10001), baked into the image `USER` | identical | none |
| Read-only rootfs | `read_only: true` | identical | none |
| tmpfs scratch | `/tmp` 256m mode 1777; `/app/data` 256m uid/gid 10001 mode 0700 | identical | none |
| Memory / PID / CPU limits | `mem_limit: 1g`, `pids_limit: 256`, `cpus: 2` | identical | none |
| Log rotation | `json-file`, 10m × 3 | identical | none |
| Restart policy | `unless-stopped` | identical | none |
| `security_opt: no-new-privileges` / `cap_drop` / explicit `user:` override | absent | **also absent** | none — repo-wide characteristic, not a self-host-specific gap (worth a future cross-cutting hardening pass, out of this track's scope) |
| Dev signer / test hooks / legacy-create | never set by `selfhost.sh init`; `check` fails closed if any appear | same application-level gate (`sdk/src/config.js`), independent of deployment mode | none |
| Rate limiting | mandatory ON whenever hosted auth is enabled (`selfhost.sh init` always sets `POLICYVAULT_HOSTED_AUTH=1`) — proven live (429 after a 56-request spray, `Retry-After` present) | identical application-level rule, same code path | none |
| CSP / security headers | identical server code path — proven live (CSP self, nosniff, no-referrer, COOP/CORP, frame-deny) | identical | none |
| PostgreSQL transport | bundled container, compose-private network, **no published port**; `POLICYVAULT_PG_NO_TLS=1` permitted on testnet only (same documented concession as the staging compose) and **refused by config on mainnet**, forcing an external TLS-capable PG | DigitalOcean Managed PostgreSQL, VPC-private endpoint, TLS, CA-pinned (`NODE_EXTRA_CA_CERTS`) | none on mainnet (config-enforced); testnet self-host matches the documented staging posture exactly |
| Ingress | loopback-only (`127.0.0.1:PORT`); exposing further is an explicit, documented operator act (own reverse proxy/tunnel) | Cloudflare named Tunnel, no published port at all | self-host correctly defaults to the *more* conservative posture (nothing reachable at all without deliberate operator action) — not weaker |
| kaspad RPC transport | operator's own node, private host-side forwarder bound to a private/loopback address only (code-enforced: refuses to bind any non-RFC1918 address) | dedicated VPC kaspad host, provider firewall | both keep RPC off the public internet; self-host puts the burden correctly on the operator's own trusted node, matching the product's non-custodial design |

**Conclusion: no self-hosted-mode weakening was found relative to hosted
production.** The one real difference (bundled non-TLS PG on testnet) is
an explicit, documented, testnet-only concession identical to what the
hosted staging environment itself uses, and is structurally closed off
on mainnet by `sdk/src/config.js`'s fail-closed gate — never a silent
downgrade.

## 7. Hidden-dependency scan

Grepped the self-hosting path files (`deploy/selfhost.sh`,
`deploy/docker-compose.selfhost.yml`, `tools/stage-vendor.sh`,
`tools/staging-kaspad-proxy.js`, `docs/selfhost-quickstart.md`) for
operator-machine-specific hostnames, paths, IPs, and usernames
(the operator's home path, the private VPC range, the production kaspad droplet's public IP,
the owner's GitHub handle, `pv-ops`/`pv_prod_ops` SSH identities): **zero
hits.** `host-kaspad` is a documented, generic compose `extra_hosts` alias
resolved via Docker's own `host-gateway` mechanism — not a hardcoded
address — and the forwarder script (`tools/staging-kaspad-proxy.js`)
auto-detects the bridge gateway and refuses to bind any non-private
address by code.

Two unrelated private production-operations templates **do** hardcode the
owner's real username and a production SSH key path (the systemd unit
templates for the owner's own mainnet kaspad droplet; they are excluded
from every public release), plus `deploy/droplet-setup.sh`'s `pv-ops` SSH
key reference. **These are out of scope for this track**:
they are not part of the self-hosting path (never referenced by
`deploy/selfhost.sh`, the selfhost compose file, `tools/stage-vendor.sh`,
or `docs/selfhost-quickstart.md`), are private production-operations
templates for the owner's own infrastructure (not shipped to or run by a
self-hoster), and are pre-existing, not introduced by this track. Noted
here for completeness only.

## 8. Reproduction commands (what an outsider actually runs)

```bash
# Prerequisites (once): Docker + compose plugin, Node 20+, openssl, a Rust
# toolchain, sibling ~/silverscript and ~/rusty-kaspa checkouts (built),
# and your own synced testnet-10 kaspad with --utxoindex.
cd ~/silverscript && cargo build
cd <policyvault-checkout>/tests/vm && cargo build

bash deploy/selfhost.sh init            # writes deploy/selfhost.env (mode 600)
node tools/staging-kaspad-proxy.js &    # your own private RPC forwarder
bash deploy/selfhost.sh up              # stages vendor if needed, builds, migrates, starts
bash deploy/selfhost.sh check           # 13/13 posture checks
bash deploy/selfhost.sh acceptance      # 37/37 externally-driven suite

bash deploy/selfhost.sh backup
bash deploy/selfhost.sh restore <file>
bash deploy/selfhost.sh upgrade         # after pulling new source
bash deploy/selfhost.sh rollback
bash deploy/selfhost.sh status
bash deploy/selfhost.sh logs
bash deploy/selfhost.sh down            # stop, keep data
bash deploy/selfhost.sh destroy         # uninstall, deletes data (explicit confirm)
```
