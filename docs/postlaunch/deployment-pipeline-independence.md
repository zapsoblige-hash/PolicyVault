# Deployment pipeline independence — removing the residential-uplink bottleneck

**Track 8 (flagship program).** Status labels for everything in this
document: **DESIGNED + IMPLEMENTED + INTEGRATION-VERIFIED (local,
non-production)**. **NOT DEPLOYED.** Nothing here has been run against
production: no SSH to any droplet, no DigitalOcean/Cloudflare API call,
no DNS change, no docker operation against a production host, no
resource provisioned, no image or source uploaded to any third party.
Every number below comes from local builds on the operator laptop.

Cost: **ZERO incremental recurring cost** for the chosen design (§6). A
cost-gated alternative is written up in §11 and is NOT provisioned.

---

## 1. The bottleneck, measured

Today every hosted release ships a whole image:

| step | today |
|---|---|
| build | operator laptop, `docker build` |
| package | `docker save` → tar (layers already gzip-compressed) |
| transfer | `scp` over a residential uplink, ~35 KB/s |
| verify | `sha256sum -c` on the droplet |
| install | `docker load`, verify image ID, `docker compose up` by tag |

Measured on this tree (`59e57dc`, Docker 29.1.3, containerd image store):

| artifact | bytes | notes |
|---|---:|---|
| image, on-disk (uncompressed) | 871 MB | `docker images` DISK USAGE |
| image, `docker save` tar | 207,922,176 | blobs are already gzip |
| image, reproducible OCI archive | 207,913,984 | `--output type=oci` (§4) |
| same, zstd-19 layers | 164,704,256 | −20.8 % (compat. note in §6.4) |
| re-compressing the save tar (gzip/zstd) | ≈ no gain | layer blobs are already compressed |

**Transfer time at 35 KB/s (35,840 B/s): 207,922,176 B → 5,801 s = 1.61 h
per deploy** — the same 1.61 h whether the change is one CSS line or the
whole application. That is the bottleneck; it is a *transfer* problem,
not a *build* problem.

### 1.1 Where the bytes are

Compressed layer sizes of the real image (from the OCI manifest, aligned
with the build history):

| # | compressed | layer |
|--:|--:|---|
| 0 | 41,569,203 | ubuntu:26.04 base rootfs |
| 2 | 4,111,216 | `apt-get install ca-certificates xz-utils` |
| 3 | 26,177,777 | COPY node-v20.20.2 tarball |
| 5 | 48,623,514 | RUN verify + unpack Node runtime |
| 8 | 177,152 | COPY core |
| 9 | 174,822 | COPY sdk/src |
| 11 | 701,466 | COPY node_modules (from `npm ci`) |
| 12 | 154,010 | COPY server/src |
| 13 | 8,384 | COPY server/migrations |
| 15 | 1,349,011 | COPY web |
| 16 | 29,285 | COPY contracts |
| 17 | 21,077,848 | COPY pv_call_encoder |
| 18 | 22,362,771 | COPY pv_vm_preflight |
| 19 | 13,309,292 | COPY pv_tx_probe |
| 20 | 23,402,961 | COPY silverc |
| 21 | 4,637,820 | COPY kaspa-wasm |
| — | 207,873,505 | total layer bytes (+ config 11,577 + manifest 6,462) |

**98.7 % of every shipped byte is content that does not change between
releases** (base OS, Node runtime, the staged Rust binaries). The nine
application layers total **2,595,200 bytes** — 1.25 % of the image.

---

## 2. Candidates evaluated

| | **A. build on/near production** | **B. image registry** | **C. signed source bundle → remote builder** | **D. reproducible build + content-addressed delta (CHOSEN)** |
|---|---|---|---|---|
| recurring cost | $0 on the app droplet; **+$24/mo** for a separate build host | DOCR/GHCR/Hub: free tiers too small or third-party hosting of a private image (**prohibited**); self-hosted registry = another service to run | $0 only if the builder is an existing production host (else +$24/mo) | **$0** |
| per-build bytes from the operator | ~1.9 MB source (bundle) | 208 MB push (unless built remotely) | 1,895,281 B (measured) | **1,382,400 B measured (one web file); ≤2.61 MB for any app-source change** |
| source confidentiality | private source + build toolchain land on the **live host** | image (and history) held by a third party | source on the builder; bundle carries only what the image already ships | **nothing new leaves the laptop** — only image layers, as today |
| dependency integrity | `npm ci` on the live host at deploy time | registry content-addressed | `npm ci` on the builder, lockfile-pinned | lockfile + vendored artifacts resolved **once, on the operator machine** |
| reproducibility | build-time floats with the host's network | n/a (transport only) | same recipe, different host — content-equivalent | **bit-reproducible export proven** (§7) |
| artifact identity | image built where it runs — no independent digest to compare | registry digest | digest computed on the builder | **digest computed on the laptop, re-derived and re-verified on the target** |
| compromise blast radius | build compromise = production compromise (same host) | registry account compromise = ability to serve a poisoned image | builder compromise poisons images but not production state | **builder = the operator laptop, already the trusted origin; no new trusted party** |
| secret exposure | production env sits beside a build toolchain | registry credentials on the droplet | none (bundle has no secrets) | **none** (delta files contain image layers only) |
| rollback | rebuild (slow, may not reproduce) | re-pull previous digest | rebuild or keep archives | **instant: previous blobs stay in the target cache; `--rollback <digest>`** |
| builder persistence | competes with the live app for 2 vCPU / 3.9 GB | n/a | dedicated builder must be maintained/patched | none required |
| supply-chain risk | registry + toolchain reachable from production at deploy time | third-party in the trust path | builder reaches npm at build time | **npm/base image reached only on the laptop; the droplet stays network-minimal** |
| dependency caching | docker cache on the live host | registry layer reuse | builder-side buildkit cache | **target-side content-addressed blob cache (this is the mechanism)** |
| deployment speed | fast transfer, slow/risky build on a 2-vCPU live host | fast if built remotely | ~45 s transfer + remote build | **~39 s transfer + `docker load`** |
| operator independence | needs SSH to production anyway | needs registry auth from production | needs SSH/transport to the builder | same SSH as today, 150× less data |
| **private git remote needed?** | yes, or a source bundle anyway | no | no (bundle, not git) | **no** |
| **failure-domain coupling** | **improper: build failures/CPU/disk hit the live app** | registry outage blocks deploys | builder is separate — acceptable | **none: production never builds, never pulls, never talks to a registry** |

Rejected, with reasons:

* **A** violates the standing production rule *"never build on the
  droplet"* (`docker-compose.prod.yml` header, runbook §10), puts a
  toolchain and npm reachability next to the live app on a 2 vCPU /
  3.9 GB host running the ONE app replica, and couples build failures to
  production availability. A *separate* build host removes the coupling
  but adds recurring cost for a problem that costs $0 to solve.
* **B** is prohibited for this repo (no image or source may be uploaded
  to any third-party service), and even where it is not, it does not fix
  the uplink: the 208 MB push leaves from the same residential link
  unless the build itself is remote (which reduces to A or C).
* **C** is sound and is *kept as the fallback path* (the scripts
  implement it fully, and the local proof exercises the builder role) —
  but it needs a builder host to exist, maintained and trusted, and it
  ships ~1.9 MB per build to save the same time D saves with **1.38 MB
  and no builder at all**. C wins only if the operator machine ever
  cannot build (e.g. a non-x86 laptop).

---

## 3. What makes D possible (the measurement that decided it)

A naive "ship only the new layers" scheme fails on this image. Building
twice with a one-line change to `web/app.js`:

| build recipe | blobs that changed | bytes to ship |
|---|--:|--:|
| current recipe (`docker build`, buildx defaults) | 14 of 28 | **86,188,584** |
| + `--provenance=false --sbom=false`, `SOURCE_DATE_EPOCH`, `rewrite-timestamp=true` | **3 of 25** | **1,367,050** |

Cause (isolated experiment, `deploy/pipeline` design notes): a cache miss
re-executes every following stage, and each re-executed `COPY` layer gets
**fresh directory timestamps**, so its diff ID and its compressed blob
change even though the copied bytes are identical. `SOURCE_DATE_EPOCH`
alone does **not** fix it (proven: layers still differed); BuildKit's
`rewrite-timestamp=true` export option does. Attestation manifests were
also removed because they give the archive two manifests and make "the
image digest" ambiguous.

Confirmed non-effects: `--build-arg BASE_IMAGE=ubuntu:26.04@sha256:2260…`
(digest pin) produced a **byte-identical** archive to the floating tag on
this machine, so the pin is provably free to adopt today (§7).

---

## 4. Chosen design

```
operator laptop (unchanged trust origin)          droplet (unchanged: never builds)
─────────────────────────────────────────         ──────────────────────────────────
bundle-source.sh   → deterministic source id      image-inventory.sh → blob list (KBs)
build-image.sh     → reproducible OCI archive            ▲
                     + exact image digest                │ (tiny, back-channel)
pack-delta.sh      → ONLY the blobs the target           │
                     does not have  ──── scp ──────────► apply-delta.sh
sign-bundle.sh     → ssh-keygen -Y signature               verify sig → verify every
                                                           blob sha256 → reassemble →
                                                           digest must match → docker load
                                                                    │
                                                    verify-before-activate.sh
                                                      privacy scan + private-container
                                                      liveness/readiness probe
                                                                    │
                                                    deploy-by-digest.sh
                                                      tag←digest, one env line, atomic,
                                                      ledger, --rollback <digest>
```

Every artifact is content-addressed; the target proves the image it
loaded is exactly the image the operator built, and refuses everything
else. The compose contract is untouched: the tag key in the env file
still selects `policyvault-app:<tag>`, and the tag is bound to a verified
digest before the env is written.

### 4.1 Scripts (`deploy/pipeline/`, shell only, no new dependencies)

| script | role | runs on |
|---|---|---|
| `pipeline-lib.sh` | atomic install, deterministic tar, OCI helpers | both |
| `bundle-source.sh` | deterministic source bundle + `SOURCE_IDENTITY` (commit, tree, content id); Dockerfile-COPY coverage self-check; reuses `tools/image-privacy-scan.sh --classify-paths` as the forbidden-path filter | operator |
| `sign-bundle.sh` / `verify-bundle.sh` | `ssh-keygen -Y sign/verify` with an `allowed_signers` file + sha256 pin | both |
| `build-image.sh` | reproducible single-manifest OCI build; temp file + atomic rename; emits digest + `*.build.json` | builder |
| `remote-build.sh` | verify signature → **fresh** context → vendor `sha256sum -c` → build | builder |
| `pack-delta.sh` | image + target inventory → ship only missing blobs | operator |
| `image-inventory.sh` | target's blob inventory (optionally re-hashing) | target |
| `apply-delta.sh` | verify sig → verify every blob → assemble → digest match → `docker load` → identity match | target |
| `verify-before-activate.sh` | digest + build-id identity, per-layer privacy scan, private-container liveness/readiness | target |
| `deploy-by-digest.sh` | bind tag to digest, single-key atomic env rewrite, activation ledger, `--rollback` | target |
| `local-proof.sh` | the non-production end-to-end proof (§8) | operator |

Docker-free regression coverage: `sdk/test/deploy-pipeline.test.js`
(5/5 pass) drives the transfer mechanics on a synthetic OCI archive —
deterministic-tar stability, the seed→delta round trip (only the changed
blobs ship, the reassembly resolves to the same digest), and the
fail-closed paths: tampered blob, unexpected digest, stale inventory,
missing `allowed_signers`, and the mainnet-env refusal (which is asserted
to leave the env file byte-identical). The existing
`sdk/test/image-scan-classify.test.js` (4/4) and
`sdk/test/hosted-deployment*.test.js` (7 + 1 pass, 10 PG/docker-gated
skips) still pass unchanged.

---

## 5. Before / after

At 35 KB/s (35,840 B/s):

| change class | before (always) | after | speed-up |
|---|--:|--:|--:|
| one web file | 207.9 MB / **1.61 h** | 1,382,400 B / **38.6 s** | **150×** |
| any/all application source (9 layers) | 207.9 MB / 1.61 h | ≈2,613,239 B / **72.9 s** | 80× |
| dependency change (`package-lock.json`) | 207.9 MB / 1.61 h | ≈1.4–2.6 MB / ≈40–73 s | ~100× |
| staged Rust binaries rebuilt | 207.9 MB / 1.61 h | ≤84,790,692 B / **39.4 min** | 2.5× |
| base image / Node runtime change | 207.9 MB / 1.61 h | ≈full ship / 1.61 h | 1× |
| **first (seed) transfer, once** | — | 207,923,200 B / 1.61 h (or 164.7 MB / 1.28 h with zstd layers) | one time |

Supporting sizes: source bundle 1,895,281 B (216 files, 4.81 MB raw);
whole-repo `git archive` 14,581,760 B (3,298,461 B zstd-19); staged
vendor artifacts 350,651,182 B (a one-time seed only for candidate C).

The seed cost is unavoidable and paid **once**: the currently deployed
image was built with the old recipe, so its blobs do not match the
reproducible recipe's blobs. Every deployment after the seed is a delta.

---

## 6. Reproducibility: what is proven, what is not

* **Bit-reproducible (proven here):** the OCI archive export. Re-running
  the same build produced a **byte-identical archive**
  (`sha256 a86db00b…` twice), and the digest-pinned base produced the
  same bytes as the floating tag. `docker load` of that archive yields an
  image ID **equal to the archive's manifest digest** (proven), which is
  what makes digest-pinned activation and rollback exact.
* **Content-equivalent, not bit-identical (honest limit):** a *cold*
  rebuild on another machine or at another time is **not** guaranteed to
  reproduce the same bytes, because two build inputs float:
  1. `ARG BASE_IMAGE=ubuntu:26.04` is a **tag, not a digest** — pin it
     with `--build-arg BASE_IMAGE=ubuntu:26.04@sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b`
     (measured: byte-identical result today, so adopting the pin costs
     nothing and removes one floating input);
  2. `apt-get update && apt-get install ca-certificates xz-utils` resolves
     against live Ubuntu archives, so the package layer can change
     without any repository change.
  Node.js (official tarball + SHASUMS256 verified in-build) and the npm
  dependency set (`npm ci` against the committed lockfile with integrity
  hashes) are already pinned, and the staged vendor artifacts are
  verified against `deploy/vendor/SHA256SUMS.txt`.
* Recommendation (owner-gated, NOT applied here): adopt the base-image
  digest pin via the existing `BASE_IMAGE` ARG — no Dockerfile edit
  required — and record the apt layer as the one remaining floating
  input. Full bit-reproducibility across time would additionally need a
  pinned apt snapshot; that is a larger change and is **not** proposed
  now.
* The production `deploy/Dockerfile` was **not modified** by this track.
  The pipeline changes only *how* the image is exported and transported.

---

## 7. Threat model

| threat | mitigation | residual |
|---|---|---|
| tampered artifact in transit | every blob is named by its own sha256 and re-hashed on the target **before anything is installed** (two passes: verify all, then install — a bundle that fails integrity anywhere installs NOTHING); the assembly must satisfy the expected image digest and `docker load` must produce that exact image ID | a wrong artifact cannot be activated, only rejected |
| forged/replayed bundle | `ssh-keygen -Y verify` against an explicit `allowed_signers` + a sha256 pin; verification happens **before** anything is unpacked (proven: a one-byte flip is rejected) | key management is the operator's; the pipeline never generates or stores a production key |
| stale target inventory (delta missing a layer) | `REQUIRED_BLOBS` lists the full set; a missing blob aborts before `docker load` with a "re-pack with a fresh inventory" error | none — fails closed, never a partial image |
| builder compromise | the builder is the operator laptop — the existing trusted origin; no new party is introduced, and the fallback C path verifies bundle signature + vendor hashes before building | a compromised laptop can build a bad image (true today as well) |
| production host compromise | unchanged: the droplet still receives only image layers, holds no build toolchain, no registry credential, no source it did not already contain in the image | unchanged from today |
| secret leaking into an image layer | `verify-before-activate.sh` runs `tools/image-privacy-scan.sh` over **every layer blob** (paths + raw bytes) of the exact digest before activation; the default-deny `.dockerignore` keeps env files, keys, data roots and `.git` out of the context | proven CLEAN on the built image (25 blobs scanned) |
| secret leaking into a transferred file | delta bundles contain image layers + a manifest only; the source bundle contains only the runtime paths the image already ships and is scanned with the same forbidden-path classifier | none observed |
| interrupted transfer/build/activation | artifacts are written to temp paths and atomically renamed; blobs install atomically into the cache; the env file is rewritten temp+rename with an assertion that exactly one line changed | a killed build can leave a `*.partial.*` file (never an artifact); the next run purges it (proven) |
| wrong image activated | the tag is re-resolved after binding and must equal the digest; the activation ledger records the previous digest for one-command rollback | none |
| production activated accidentally by this tooling | `deploy-by-digest.sh` refuses any env file marked mainnet unless `PV_PIPELINE_ALLOW_PRODUCTION_ENV=1` is set explicitly | the owner gate is deliberate (§10) |

---

## 8. Local proof (non-production) — executed 2026-09-03

`deploy/pipeline/local-proof.sh --workdir <scratch>`; full transcript in
`docs/postlaunch/deployment-pipeline-local-proof.txt`. Scratch tags,
scratch compose project, a scratch TEST signing key, testnet-10 + json
persistence, loopback only.

| proof | result |
|---|---|
| P1 deterministic source bundle + signature; **negative**: one flipped byte | 1,895,281 B signed and verified; tampered bundle **REJECTED** |
| P2 builder role: build from the *verified* bundle in a fresh context | `sha256:c87990f8…`, base pinned by digest |
| P3 seed transfer → apply → load | 207,923,200 B shipped; loaded image ID **==** built digest |
| P4 one-file change → delta | **1,382,400 B (0.66 % of the image, 150.4× less; 38.6 s vs 1.61 h)**; loaded image ID **==** built digest `sha256:be5cc657…` |
| P5 verify-before-activate | privacy scan CLEAN (25 blobs); liveness + `/health/ready` 200 with the expected buildId |
| P6 activate by digest, then `--rollback` | serving buildId `59e57dc` → `59e57dc.07e297cc` → `59e57dc` again; **0** non-tag env lines changed across two activations and one rollback; ledger recorded both |
| P7 interrupted build | SIGKILL mid-build ⇒ **no final artifact**; rerun produced a complete archive whose digest re-derives from the file; a planted stale partial was purged |

Finding folded back into the tooling: the server validates
`POLICYVAULT_BUILD_ID` as `[A-Za-z0-9._-]{1,64}` and fails closed — the
bundle's dirty-tree identity separator was changed to `.` so a modified
tree still produces a startable, unambiguous build id
(`<short-commit>.<content-id prefix>`, never the bare commit).

---

## 9. Operator procedure (when the owner authorizes running it)

```bash
# ── on the target, once (or whenever the inventory is stale) ──────────
deploy/pipeline/image-inventory.sh --cache /opt/policyvault/imgcache --out inv.txt
#   copy inv.txt back to the laptop (kilobytes)

# ── on the operator laptop ────────────────────────────────────────────
tools/stage-vendor.sh
deploy/pipeline/build-image.sh --context . --out /tmp/pv.oci.tar \
  --base ubuntu:26.04@sha256:<pinned>        # prints the image digest
deploy/pipeline/pack-delta.sh --image /tmp/pv.oci.tar --out ship.tar --inventory inv.txt
deploy/pipeline/sign-bundle.sh --file ship.tar --key ~/.ssh/<operator key>
scp ship.tar ship.tar.sig <target>:/opt/policyvault/incoming/

# ── on the target ─────────────────────────────────────────────────────
deploy/pipeline/apply-delta.sh --bundle ship.tar --cache /opt/policyvault/imgcache \
  --allowed-signers /opt/policyvault/allowed_signers --identity <operator id> \
  --expect-digest sha256:<digest> --tag policyvault-app:<new tag>
deploy/pipeline/verify-before-activate.sh --digest sha256:<digest> --repo <checkout> \
  --expect-build-id <buildId>
PV_PIPELINE_ALLOW_PRODUCTION_ENV=1 \
deploy/pipeline/deploy-by-digest.sh --digest sha256:<digest> --tag <new tag> \
  --env /opt/policyvault/prod.env --compose /opt/policyvault/docker-compose.prod.yml --apply
# rollback: the exact command is printed and recorded in the ledger
```

Unchanged production discipline: migrations stay an explicit one-shot
step, the app never auto-migrates, ONE app replica, DNS is never touched
by this pipeline, the webhook secret is never read or written, and no env
value other than the image-tag key is modified.

---

## 10. What remains OWNER-GATED

1. **Running any of this against production** (SSH to the droplet, the
   seed transfer, the first digest activation). Nothing in this track was
   run against production.
2. **The one-time seed transfer** (1.61 h, or 1.28 h with zstd layers) —
   it changes the deployed image's *bytes* (rewritten timestamps), so it
   is a normal release candidate needing the usual acceptance, not a
   silent swap.
3. **Adopting the base-image digest pin** (measured byte-identical today).
4. **Any recurring cost** — none is proposed; §11 exists only so the
   option is priced if the owner ever wants it.
5. **Switching layer compression to zstd** (−20.8 %): requires confirming
   the target's docker supports zstd layers.

## 11. COST-GATED alternative (NOT provisioned, NOT recommended)

Only if the owner ever wants a builder independent of the laptop:

| item | spec | cost |
|---|---|---|
| dedicated build droplet | DO s-2vcpu-4gb, sfo3, on the existing VPC | **+$24/mo** (+ ~$5/mo optional snapshots) |
| firewall change | SSH from the operator /32 only; **no** ingress from the app droplet; egress to npm/registries | $0 |
| what it buys | candidate C end-to-end without the laptop; ~1.9 MB/build from the operator | — |
| what it costs beyond money | one more host to patch and trust; a second machine that can produce production images | — |

**Do not provision this without an explicit owner cost approval.** The
chosen design achieves the same deployment latency at $0 and with one
fewer trusted machine.

## 12. Residuals

* The apt layer remains a floating build input (§6).
* The seed transfer is still 1.61 h once; nothing can avoid a first full
  image over this uplink.
* The real-docker path is exercised by `local-proof.sh` on demand, not by
  a CI suite; only the docker-free mechanics are covered by
  `sdk/test/deploy-pipeline.test.js`.
* A vendor-toolchain rebuild still ships ~85 MB (39 min) — improvable
  only by shipping release-profile (smaller) binaries, which is a
  separate, evidence-gated decision.
