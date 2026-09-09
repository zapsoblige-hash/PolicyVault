#!/usr/bin/env bash
# Build a PolicyVault image FROM A SIGNED SOURCE BUNDLE in a fresh,
# throwaway context (runs on whichever machine is the builder).
#
#   deploy/pipeline/remote-build.sh --bundle <bundle.tgz> --vendor <dir> \
#       --workdir <scratch> --out <oci.tar> \
#       [--allowed-signers <f> --identity <id> --sig <f>] \
#       [--base <img@sha256:..>] [--sha256 <expected>] [--compression gzip|zstd]
#
# Fails closed before ANY untrusted byte is executed or built:
#   signature + sha256 -> clean context (fresh dir, never a reused one)
#   -> vendor artifacts verified against deploy/vendor/SHA256SUMS.txt
#   -> deterministic build (build-image.sh) -> exact image digest printed.
# The bundle carries no secrets and no .git; the builder needs no
# repository access, no private git remote, and no credentials.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/pipeline-lib.sh"

BUNDLE=""; VENDOR=""; WORKDIR=""; OUT=""; ALLOWED=""; IDENTITY=""; SIG=""; BASE=""; EXPECT=""; COMPRESSION="gzip"
while [ $# -gt 0 ]; do
  case "$1" in
    --bundle) BUNDLE="$2"; shift 2;;
    --vendor) VENDOR="$2"; shift 2;;
    --workdir) WORKDIR="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --allowed-signers) ALLOWED="$2"; shift 2;;
    --identity) IDENTITY="$2"; shift 2;;
    --sig) SIG="$2"; shift 2;;
    --base) BASE="$2"; shift 2;;
    --sha256) EXPECT="$2"; shift 2;;
    --compression) COMPRESSION="$2"; shift 2;;
    *) pv_die "unknown argument: $1";;
  esac
done
[ -n "$BUNDLE" ] && [ -n "$VENDOR" ] && [ -n "$WORKDIR" ] && [ -n "$OUT" ] \
  || pv_die "usage: remote-build.sh --bundle <b.tgz> --vendor <dir> --workdir <scratch> --out <oci.tar> [--allowed-signers f --identity id] [--base img@sha256:..] [--sha256 x] [--compression gzip|zstd]"
pv_need tar; pv_need docker
[ -f "$BUNDLE" ] || pv_die "no such bundle: $BUNDLE"
[ -f "$VENDOR/SHA256SUMS.txt" ] || pv_die "vendor dir has no SHA256SUMS.txt: $VENDOR (run tools/stage-vendor.sh)"

if [ -n "$ALLOWED" ] || [ -n "$IDENTITY" ]; then
  [ -n "$ALLOWED" ] && [ -n "$IDENTITY" ] || pv_die "need BOTH --allowed-signers and --identity"
  "$HERE/verify-bundle.sh" --file "$BUNDLE" ${SIG:+--sig "$SIG"} --allowed-signers "$ALLOWED" --identity "$IDENTITY" ${EXPECT:+--sha256 "$EXPECT"} >/dev/null
elif [ -n "$EXPECT" ]; then
  ACT="$(pv_sha256 "$BUNDLE")"; [ "$ACT" = "$EXPECT" ] || pv_die "bundle sha256 mismatch: $ACT != $EXPECT"
  pv_log "WARNING: bundle sha256 matched but NO signature was verified"
else
  pv_die "refusing to build unauthenticated source: pass --allowed-signers/--identity (or at least --sha256)"
fi

# Vendor integrity (the staged binaries are the image's trusted runtime).
( cd "$VENDOR" && sha256sum -c --quiet SHA256SUMS.txt ) || pv_die "VENDOR ARTIFACT VERIFICATION FAILED in $VENDOR"

# Clean context: a FRESH directory every time (never build over the
# remains of an interrupted previous build).
CTX="$WORKDIR/ctx.$(date +%s).$$"
rm -rf "$CTX"; mkdir -p "$CTX"
trap 'rm -rf "$CTX"' EXIT
tar -xzf "$BUNDLE" -C "$CTX"
[ -f "$CTX/SOURCE_IDENTITY" ] || pv_die "bundle carries no SOURCE_IDENTITY"
mkdir -p "$CTX/deploy"
cp -r "$VENDOR" "$CTX/deploy/vendor"
pv_log "context: $CTX ($(grep -c . "$CTX/SOURCE_IDENTITY") identity lines, commit $(awk -F= '$1=="short_commit"{print $2}' "$CTX/SOURCE_IDENTITY"))"

DIGEST="$("$HERE/build-image.sh" --context "$CTX" --out "$OUT" --compression "$COMPRESSION" ${BASE:+--base "$BASE"})"
pv_log "remote build complete: $DIGEST"
printf '%s\n' "$DIGEST"
