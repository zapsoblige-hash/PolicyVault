#!/usr/bin/env bash
# Deterministic PolicyVault image build → single-manifest OCI archive.
#
#   deploy/pipeline/build-image.sh --context <dir> --out <oci.tar> \
#       [--build-id <id>] [--base <ubuntu:26.04@sha256:...>] \
#       [--epoch <unix-seconds>] [--name <repo:tag>] [--compression gzip|zstd]
#
# WHY these flags (measured — docs/postlaunch/deployment-pipeline-independence.md):
#   --provenance=false --sbom=false  -> exactly ONE image manifest, so the
#       archive's image digest is unambiguous and `docker load` reproduces
#       it as the image ID (attestation manifests break digest identity).
#   SOURCE_DATE_EPOCH + rewrite-timestamp=true -> layer timestamps are
#       rewritten to a fixed epoch, so layers that did not change keep
#       their exact diff/blob digests across builds. Without it a
#       one-file web change re-timestamps every following layer and the
#       transfer delta is 86 MB instead of 1.3 MB (measured).
#   --build-arg BASE_IMAGE=<...@sha256:...> -> pins the base by digest
#       through the Dockerfile's EXISTING ARG (no Dockerfile edit).
#
# The archive is written to a temp path and atomically renamed, so an
# interrupted or killed build never leaves a partial artifact that a
# later step could mistake for a complete one.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/pipeline/pipeline-lib.sh
. "$HERE/pipeline-lib.sh"

CONTEXT=""; OUT=""; BUILD_ID=""; BASE=""; EPOCH=""; NAME="policyvault-app:pipeline"; COMPRESSION="gzip"
while [ $# -gt 0 ]; do
  case "$1" in
    --context) CONTEXT="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --build-id) BUILD_ID="$2"; shift 2;;
    --base) BASE="$2"; shift 2;;
    --epoch) EPOCH="$2"; shift 2;;
    --name) NAME="$2"; shift 2;;
    --compression) COMPRESSION="$2"; shift 2;;
    *) pv_die "unknown argument: $1";;
  esac
done
[ -n "$CONTEXT" ] && [ -n "$OUT" ] || pv_die "usage: build-image.sh --context <dir> --out <oci.tar> [--build-id id] [--base img@sha256:..] [--epoch N] [--name repo:tag] [--compression gzip|zstd]"
pv_need docker; pv_need tar; pv_need sha256sum
[ -d "$CONTEXT" ] || pv_die "context is not a directory: $CONTEXT"
[ -f "$CONTEXT/deploy/Dockerfile" ] || pv_die "context has no deploy/Dockerfile: $CONTEXT"
[ -f "$CONTEXT/.dockerignore" ] || pv_die "context has no .dockerignore — the default-deny build-context filter is part of the security boundary"
[ -d "$CONTEXT/deploy/vendor" ] || pv_die "context has no deploy/vendor — run tools/stage-vendor.sh on the builder first"
case "$COMPRESSION" in gzip|zstd) ;; *) pv_die "unknown compression: $COMPRESSION (gzip|zstd)";; esac

# Build identity + epoch default to the source commit when the context is
# a git checkout; otherwise they must be supplied (never guessed).
if [ -z "$BUILD_ID" ] || [ -z "$EPOCH" ]; then
  if [ -f "$CONTEXT/SOURCE_IDENTITY" ]; then
    [ -n "$BUILD_ID" ] || BUILD_ID="$(awk -F= '$1=="short_commit"{print $2}' "$CONTEXT/SOURCE_IDENTITY")"
    [ -n "$EPOCH" ]    || EPOCH="$(awk -F= '$1=="epoch"{print $2}' "$CONTEXT/SOURCE_IDENTITY")"
  elif git -C "$CONTEXT" rev-parse --git-dir >/dev/null 2>&1; then
    [ -n "$BUILD_ID" ] || BUILD_ID="$(git -C "$CONTEXT" rev-parse --short HEAD)"
    [ -n "$EPOCH" ]    || EPOCH="$(git -C "$CONTEXT" log -1 --format=%ct)"
  fi
fi
[ -n "$BUILD_ID" ] || pv_die "no --build-id and no source identity in the context — refusing to build an unidentified image"
[ -n "$EPOCH" ] || pv_die "no --epoch and no source identity in the context — refusing a non-deterministic build"
case "$EPOCH" in ''|*[!0-9]*) pv_die "epoch must be unix seconds: $EPOCH";; esac

OUT_DIR="$(cd "$(dirname "$OUT")" && pwd)"; OUT="$OUT_DIR/$(basename "$OUT")"
TMP_OUT="$OUT.partial.$$"
# Clear any leftovers from a previously KILLED build (they can never be
# mistaken for a finished artifact — only the atomic rename produces $OUT).
rm -f "$OUT".partial.* "$TMP_OUT"
trap 'rm -f "$TMP_OUT"' EXIT

BASE_ARG=()
if [ -n "$BASE" ]; then BASE_ARG=(--build-arg "BASE_IMAGE=$BASE"); fi

pv_log "building: context=$CONTEXT buildId=$BUILD_ID epoch=$EPOCH base=${BASE:-<Dockerfile default (UNPINNED)>} compression=$COMPRESSION"
( cd "$CONTEXT" && SOURCE_DATE_EPOCH="$EPOCH" docker build \
    -f deploy/Dockerfile \
    "${BASE_ARG[@]}" \
    --build-arg "POLICYVAULT_BUILD_ID=$BUILD_ID" \
    --provenance=false --sbom=false \
    --output "type=oci,dest=$TMP_OUT,rewrite-timestamp=true,compression=$COMPRESSION,force-compression=true,name=$NAME" \
    . ) 1>&2

[ -s "$TMP_OUT" ] || pv_die "build produced no archive"
DIGEST="$(pv_oci_image_digest "$TMP_OUT")"
pv_require_digest_format "$DIGEST"
pv_atomic_install "$TMP_OUT" "$OUT"
trap - EXIT

ARCHIVE_SHA="$(pv_sha256 "$OUT")"
BYTES="$(stat -c '%s' "$OUT")"
cat > "$OUT.build.json" <<JSON
{
  "artifact": "policyvault-app-oci-archive",
  "image_digest": "$DIGEST",
  "image_name": "$NAME",
  "build_id": "$BUILD_ID",
  "source_date_epoch": $EPOCH,
  "base_image": "${BASE:-UNPINNED}",
  "compression": "$COMPRESSION",
  "archive_bytes": $BYTES,
  "archive_sha256": "$ARCHIVE_SHA",
  "docker_version": "$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)",
  "built_at_host_epoch": $(date +%s)
}
JSON
pv_log "image digest : $DIGEST"
pv_log "archive      : $OUT ($BYTES bytes, sha256 $ARCHIVE_SHA)"
printf '%s\n' "$DIGEST"
