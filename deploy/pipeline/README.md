# PolicyVault deployment pipeline (`deploy/pipeline/`)

Ships a new application image to a deployment target over a slow link by
transferring **only the layers the target does not already have**, and
activating **only an exact, verified image digest**.

Design, measurements, threat model and the operator procedure:
`docs/postlaunch/deployment-pipeline-independence.md`.
Local end-to-end proof transcript (non-production):
`docs/postlaunch/deployment-pipeline-local-proof.txt`.

Status: **DESIGNED + IMPLEMENTED + INTEGRATION-VERIFIED (local,
non-production). NOT DEPLOYED.** Running any of this against production
is an explicit owner-gated action; `deploy-by-digest.sh` refuses a
mainnet env file unless `PV_PIPELINE_ALLOW_PRODUCTION_ENV=1` is set.

| script | runs on | does |
|---|---|---|
| `bundle-source.sh` | operator | deterministic, privacy-scanned source bundle + identity |
| `sign-bundle.sh` / `verify-bundle.sh` | both | `ssh-keygen -Y` signature over an artifact + sha256 pin |
| `build-image.sh` | builder | reproducible single-manifest OCI archive + digest |
| `remote-build.sh` | builder | verified bundle → fresh context → `build-image.sh` |
| `image-inventory.sh` | target | blob inventory (a few KB, sent back to the operator) |
| `pack-delta.sh` | operator | image + inventory → only the missing blobs |
| `apply-delta.sh` | target | verify → install → assemble → `docker load` → identity check |
| `verify-before-activate.sh` | target | digest + build id, per-layer privacy scan, private readiness probe |
| `deploy-by-digest.sh` | target | bind tag ← digest, one-line atomic env change, ledger, `--rollback` |
| `local-proof.sh` | operator | the non-production end-to-end proof |

Dependencies: bash, coreutils, tar, git, docker, OpenSSH's `ssh-keygen`.
Nothing else is installed or required.

Quick local demo (safe: scratch tags, TEST key, testnet-10, loopback):

    deploy/pipeline/local-proof.sh --workdir /var/tmp/pv-pipeline-demo
