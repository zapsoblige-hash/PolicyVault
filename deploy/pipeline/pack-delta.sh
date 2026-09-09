#!/usr/bin/env bash
# Pack a CONTENT-ADDRESSED IMAGE DELTA for transfer (runs on the builder /
# owner machine).
#
#   deploy/pipeline/pack-delta.sh --image <oci.tar> --out <delta.tar> \
#       [--inventory <target-inventory.txt>] [--label <text>]
#
# Ships only the blobs the target does not already have. Because every
# blob is named by its own sha256 and the image manifest lists exactly
# which blobs the image requires, the target can reconstruct a
# byte-identical archive and prove it: an incomplete or wrong delta
# cannot produce the expected image digest.
#
# Measured on the real PolicyVault image (see
# docs/postlaunch/deployment-pipeline-independence.md): a one-web-file
# change ships 1.30 MiB instead of 198 MiB.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/pipeline-lib.sh"

IMG=""; OUT=""; INV=""; LABEL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --image) IMG="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --inventory) INV="$2"; shift 2;;
    --label) LABEL="$2"; shift 2;;
    *) pv_die "unknown argument: $1";;
  esac
done
[ -n "$IMG" ] && [ -n "$OUT" ] || pv_die "usage: pack-delta.sh --image <oci.tar> --out <delta.tar> [--inventory <file>] [--label text]"
pv_need tar; pv_need sha256sum
[ -f "$IMG" ] || pv_die "no such image archive: $IMG"

DIGEST="$(pv_oci_image_digest "$IMG")"
pv_require_digest_format "$DIGEST"
BUILD_ID=""
if [ -f "$IMG.build.json" ]; then BUILD_ID="$(grep -o '"build_id": *"[^"]*"' "$IMG.build.json" | sed 's/.*"build_id": *"//;s/"$//')"; fi

STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
pv_oci_blobs "$IMG" > "$STAGE/required.txt"
[ -s "$STAGE/required.txt" ] || pv_die "image archive lists no blobs"

: > "$STAGE/have.txt"
if [ -n "$INV" ]; then
  [ -f "$INV" ] || pv_die "no such inventory: $INV"
  LC_ALL=C sort -u "$INV" > "$STAGE/have.txt"
fi

awk '{print $1}' "$STAGE/required.txt" | LC_ALL=C sort > "$STAGE/req-names.txt"
LC_ALL=C comm -23 "$STAGE/req-names.txt" "$STAGE/have.txt" > "$STAGE/ship.txt"

mkdir -p "$STAGE/pack/blobs/sha256"
tar -xf "$IMG" -C "$STAGE/pack" index.json oci-layout
SHIP_BYTES=0
if [ -s "$STAGE/ship.txt" ]; then
  sed 's|^|blobs/sha256/|' "$STAGE/ship.txt" > "$STAGE/ship-paths.txt"
  tar -xf "$IMG" -C "$STAGE/pack" --files-from="$STAGE/ship-paths.txt"
  SHIP_BYTES="$(find "$STAGE/pack/blobs" -type f -printf '%s\n' | awk '{s+=$1} END {print s+0}')"
fi
cp "$STAGE/required.txt" "$STAGE/pack/REQUIRED_BLOBS"
TOTAL_BYTES="$(awk '{s+=$2} END {print s+0}' "$STAGE/required.txt")"
cat > "$STAGE/pack/DELTA_MANIFEST" <<MAN
schema=policyvault.image-delta/1
image_digest=$DIGEST
build_id=$BUILD_ID
label=$LABEL
required_blobs=$(wc -l < "$STAGE/required.txt")
shipped_blobs=$(wc -l < "$STAGE/ship.txt")
shipped_bytes=$SHIP_BYTES
full_image_bytes=$TOTAL_BYTES
MAN

pv_tar_deterministic "$STAGE/pack" "$STAGE/delta.tar" 0
OUT_DIR="$(cd "$(dirname "$OUT")" && pwd)"; OUT="$OUT_DIR/$(basename "$OUT")"
pv_atomic_install "$STAGE/delta.tar" "$OUT"
BYTES="$(stat -c '%s' "$OUT")"; SHA="$(pv_sha256 "$OUT")"
pv_log "delta: $OUT"
pv_log "  image digest   : $DIGEST"
pv_log "  blobs required : $(wc -l < "$STAGE/required.txt") ($TOTAL_BYTES bytes total)"
pv_log "  blobs shipped  : $(wc -l < "$STAGE/ship.txt") ($SHIP_BYTES bytes)"
pv_log "  bundle bytes   : $BYTES (sha256 $SHA)"
printf '%s\n' "$SHA"
