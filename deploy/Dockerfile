# PolicyVault hosted application image (Phase E).
#
# Build context = repository root, filtered by the DEFAULT-DENY
# .dockerignore (only the exact runtime paths enter the context at all).
# Build:   tools/stage-vendor.sh && docker build -f deploy/Dockerfile \
#            --build-arg POLICYVAULT_BUILD_ID=$(git rev-parse --short HEAD) \
#            -t policyvault-app .
#
# Security posture:
#   - base image pinned (BASE_IMAGE arg; the resolved digest is recorded
#     in the Phase E evidence and pinned below once resolved)
#   - Node.js installed from the OFFICIAL release tarball, verified
#     against the official SHASUMS256 inside the build (v20.20.2 — the
#     exact runtime the release gate ran)
#   - deterministic dependencies: `npm ci --omit=dev` against the
#     committed lockfile; no upgrades, no toolchains in the final image
#   - non-root runtime user (pv, uid 10001); application code and vendor
#     binaries are ROOT-owned and read-only to pv (a compromised app
#     cannot rewrite its own code, the covenant compiler, or the VM
#     preflight binary); the ONLY writable path is the data root
#   - no secrets, no .git, no runtime data, no private notes (default-
#     deny context + the automated image privacy scan in
#     tools/image-privacy-scan.sh)
#   - HEALTHCHECK probes /api/v1/health/ready (real readiness: database
#     reachable + schema current + network stamp — never a bare TCP ping)
#   - the server itself never auto-migrates; run the migrate service
#     first (advisory-locked, concurrency-safe)

ARG BASE_IMAGE=ubuntu:26.04

# ---------- base: pinned OS + verified Node runtime ----------
FROM ${BASE_IMAGE} AS runtime-base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates xz-utils \
 && rm -rf /var/lib/apt/lists/*
COPY deploy/vendor/dist/node-v20.20.2-linux-x64.tar.xz /tmp/node.tar.xz
COPY deploy/vendor/dist/node-SHASUMS256.txt /tmp/node-SHASUMS256.txt
RUN cd /tmp \
 && cp node.tar.xz node-v20.20.2-linux-x64.tar.xz \
 && grep " node-v20.20.2-linux-x64.tar.xz$" node-SHASUMS256.txt | sha256sum -c - \
 && tar -xJf node.tar.xz -C /usr/local --strip-components=1 \
 && rm -f /tmp/node.tar.xz /tmp/node-v20.20.2-linux-x64.tar.xz /tmp/node-SHASUMS256.txt \
 && node --version

# ---------- deps: deterministic production dependency install ----------
FROM runtime-base AS deps
WORKDIR /app/sdk
COPY sdk/package.json sdk/package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# ---------- runtime ----------
FROM runtime-base AS runtime
RUN useradd --system --create-home --home-dir /home/pv --uid 10001 --shell /usr/sbin/nologin pv
WORKDIR /app

# Application code (root-owned: read-only to the runtime user).
# core/ carries the portable shared-core (PostLaunchUpgradeOG); the sdk
# re-export shims resolve ../../core/model at runtime, so it must be in
# the image alongside sdk/src.
COPY core /app/core
COPY sdk/src /app/sdk/src
COPY sdk/package.json /app/sdk/package.json
COPY --from=deps /app/sdk/node_modules /app/sdk/node_modules
COPY server/src /app/server/src
COPY server/migrations /app/server/migrations
COPY server/package.json /app/server/package.json
COPY web /app/web
COPY contracts /app/contracts

# Staged authoritative runtime artifacts (tools/stage-vendor.sh; exact
# SHA256s in deploy/vendor/SHA256SUMS.txt, recorded in the evidence):
#  - pv_* binaries at the repo-relative path the SDK resolves
#  - silverc + kaspa-wasm at the HOME-anchored prerequisite paths
COPY deploy/vendor/bin/pv_call_encoder /app/tests/vm/target/debug/pv_call_encoder
COPY deploy/vendor/bin/pv_vm_preflight /app/tests/vm/target/debug/pv_vm_preflight
COPY deploy/vendor/bin/pv_tx_probe /app/tests/vm/target/debug/pv_tx_probe
COPY deploy/vendor/bin/silverc /home/pv/silverscript/target/debug/silverc
COPY deploy/vendor/kaspa /home/pv/rusty-kaspa/wasm/nodejs/kaspa

# Read-only code for pv; the data root is the ONLY writable path.
RUN chmod -R a+rX /app /home/pv/silverscript /home/pv/rusty-kaspa \
 && chmod 755 /app/tests/vm/target/debug/* /home/pv/silverscript/target/debug/silverc \
 && mkdir -p /app/data && chown pv:pv /app/data && chmod 700 /app/data

ENV HOME=/home/pv \
    NODE_ENV=production \
    POLICYVAULT_DATA_ROOT=/app/data

# Non-secret build identity (stale-deployment protection; /health reports it).
ARG POLICYVAULT_BUILD_ID=
ENV POLICYVAULT_BUILD_ID=${POLICYVAULT_BUILD_ID}

USER pv
EXPOSE 3080

# Readiness-based healthcheck: the container is healthy only when the
# durable backend is provably serviceable (DB reachable + schema current
# + network stamp) — no credentials in the probe or its output.
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
  CMD ["node", "-e", "fetch(`http://127.0.0.1:${process.env.POLICYVAULT_API_PORT||3080}/api/v1/health/ready`).then((r)=>process.exit(r.status===200?0:1)).catch(()=>process.exit(1))"]

ENTRYPOINT ["node", "/app/server/src/server.js"]
