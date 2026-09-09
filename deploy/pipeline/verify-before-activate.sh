#!/usr/bin/env bash
# Prove a candidate image before anything switches to it.
#
#   deploy/pipeline/verify-before-activate.sh --digest sha256:... --repo <checkout> \
#       [--expect-build-id <id>] [--network-id testnet-10] [--env-file <f>] [--skip-privacy-scan]
#
# Three independent proofs, all fail-closed:
#   1. IDENTITY  — the image with that exact digest exists locally and its
#                  configured POLICYVAULT_BUILD_ID is the expected one;
#   2. PRIVACY   — tools/image-privacy-scan.sh over EVERY layer blob
#                  (paths + raw bytes): no private repo material, no key
#                  material, no env files, no data roots in any layer;
#   3. LIVENESS  — the image is started as a PRIVATE container (no
#                  published ports, no network exposure) and probed from
#                  INSIDE via its own runtime; /api/v1/health must report
#                  the expected buildId and /api/v1/health/ready must be
#                  200 before the image is considered activatable.
# The container is always removed, including on failure.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/pipeline-lib.sh"

DIGEST=""; REPO=""; EXPECT_BUILD=""; NETWORK="testnet-10"; ENV_FILE=""; SKIP_SCAN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --digest) DIGEST="$2"; shift 2;;
    --repo) REPO="$2"; shift 2;;
    --expect-build-id) EXPECT_BUILD="$2"; shift 2;;
    --network-id) NETWORK="$2"; shift 2;;
    --env-file) ENV_FILE="$2"; shift 2;;
    --skip-privacy-scan) SKIP_SCAN=1; shift;;
    *) pv_die "unknown argument: $1";;
  esac
done
[ -n "$DIGEST" ] || pv_die "usage: verify-before-activate.sh --digest sha256:... --repo <checkout> [--expect-build-id id] [--network-id id] [--env-file f]"
pv_require_digest_format "$DIGEST"
pv_need docker

# 1. identity
LOADED="$(docker image inspect "$DIGEST" --format '{{.Id}}' 2>/dev/null || true)"
[ "$LOADED" = "$DIGEST" ] || pv_die "image $DIGEST is not present locally (docker reports '$LOADED') — load it first, never pull"
IMG_BUILD="$(docker image inspect "$DIGEST" --format '{{range .Config.Env}}{{println .}}{{end}}' | awk -F= '$1=="POLICYVAULT_BUILD_ID"{print $2}')"
pv_log "identity OK: $DIGEST buildId=${IMG_BUILD:-<unset>}"
if [ -n "$EXPECT_BUILD" ] && [ "$IMG_BUILD" != "$EXPECT_BUILD" ]; then
  pv_die "BUILD ID MISMATCH: image carries '${IMG_BUILD:-<unset>}', expected '$EXPECT_BUILD'"
fi

# 2. privacy (every layer of the exact digest)
if [ "$SKIP_SCAN" = 0 ]; then
  [ -n "$REPO" ] && [ -x "$REPO/tools/image-privacy-scan.sh" ] || pv_die "--repo <checkout with tools/image-privacy-scan.sh> is required (or --skip-privacy-scan for a re-verification of an already-scanned digest)"
  "$REPO/tools/image-privacy-scan.sh" "$DIGEST" >&2 || pv_die "IMAGE PRIVACY SCAN FAILED for $DIGEST"
fi

# 3. liveness in a private container (no ports published, no volumes)
CID=""
cleanup() { [ -n "$CID" ] && docker rm -f "$CID" >/dev/null 2>&1 || true; }
trap cleanup EXIT
if [ -n "$ENV_FILE" ]; then
  [ -f "$ENV_FILE" ] || pv_die "no such env file: $ENV_FILE"
  CID="$(docker run -d --env-file "$ENV_FILE" -e POLICYVAULT_BIND_ADDRESS=127.0.0.1 "$DIGEST")"
else
  CID="$(docker run -d -e "KASPA_NETWORK_ID=$NETWORK" -e POLICYVAULT_PERSISTENCE=json \
          -e POLICYVAULT_BIND_ADDRESS=127.0.0.1 "$DIGEST")"
fi
probe() { docker exec "$CID" node -e '
const p=process.env.POLICYVAULT_API_PORT||3080;
fetch(`http://127.0.0.1:${p}/api/v1/'"$1"'`).then(async r=>{
  console.log(JSON.stringify({status:r.status,body:await r.json()}));
  process.exit(r.status===200?0:1);
}).catch(e=>{console.log(JSON.stringify({error:String(e)}));process.exit(1);});' 2>/dev/null; }

ok=0
for i in 1 2 3 4 5 6 7 8 9 10; do
  if out="$(probe health)"; then ok=1; break; fi
  sleep 2
done
[ "$ok" = 1 ] || { pv_log "container state: $(docker inspect "$CID" --format '{{.State.Status}} exit={{.State.ExitCode}}' 2>&1)"; docker logs "$CID" 2>&1 | tail -20 >&2; pv_die "LIVENESS PROBE FAILED (/api/v1/health never answered 200)"; }
pv_log "liveness: $out"
RUN_BUILD="$(printf '%s' "$out" | sed -n 's/.*"buildId":"\([^"]*\)".*/\1/p')"
if [ -n "$IMG_BUILD" ] && [ "$RUN_BUILD" != "$IMG_BUILD" ]; then
  pv_die "RUNNING buildId '$RUN_BUILD' != image buildId '$IMG_BUILD'"
fi
if ready="$(probe health/ready)"; then pv_log "readiness: $ready"; else
  pv_log "readiness: $ready"; pv_die "READINESS PROBE FAILED (/api/v1/health/ready not 200)"; fi
pv_log "VERIFY-BEFORE-ACTIVATE: PASS ($DIGEST)"
