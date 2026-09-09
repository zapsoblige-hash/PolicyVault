#!/usr/bin/env bash
# Blob inventory of a deployment target (runs ON the target host).
#
#   deploy/pipeline/image-inventory.sh --cache <dir> [--out <file>]
#
# Prints one content-addressed blob name (sha256 hex) per line — exactly
# the layers the target already holds. The operator copies this tiny file
# back (a few KB) so pack-delta.sh can ship ONLY what is missing.
#
# The inventory is derived from the blob cache, never from `docker save`
# of a loaded image: a re-export is a different pipeline and may produce
# different compressed blobs, so trusting it would silently drop needed
# layers. Blobs whose bytes do not hash to their own name are reported
# and EXCLUDED (fail closed → they get re-shipped).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/pipeline-lib.sh"

CACHE=""; OUT=""; VERIFY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --cache) CACHE="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --verify) VERIFY=1; shift;;
    *) pv_die "unknown argument: $1";;
  esac
done
[ -n "$CACHE" ] || pv_die "usage: image-inventory.sh --cache <dir> [--out <file>] [--verify]"
mkdir -p "$CACHE/blobs/sha256"

TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
bad=0
while IFS= read -r name; do
  [ -n "$name" ] || continue
  case "$name" in *[!0-9a-f]*|"") pv_log "SKIP non-content-addressed entry: $name"; bad=1; continue;; esac
  if [ "$VERIFY" = 1 ]; then
    actual="$(pv_sha256 "$CACHE/blobs/sha256/$name")"
    if [ "$actual" != "$name" ]; then pv_log "CORRUPT blob excluded: $name (hashes to $actual)"; bad=1; continue; fi
  fi
  printf '%s\n' "$name"
done < <(find "$CACHE/blobs/sha256" -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort) > "$TMP"

if [ -n "$OUT" ]; then pv_atomic_install "$TMP" "$OUT"; trap - EXIT; pv_log "inventory: $OUT ($(wc -l < "$OUT") blobs)"
else cat "$TMP"; fi
[ "$bad" = 0 ] || pv_log "NOTE: excluded entries above will be re-shipped by the next delta"
