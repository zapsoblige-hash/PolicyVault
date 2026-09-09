#!/usr/bin/env bash
# Every layer, metadata and nested payload is decoded and scanned by the
# binary-safe gate. Exit0=classified clean,1=findings,2=incomplete/error.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
case "${1:-}" in
 --classify-paths) exec python3 "$ROOT/tools/artifact-privacy-scan.py" --classify-paths ;;
 --archive) ARCHIVE="${2:?archive path required}"; shift 2 ;;
 '') echo 'usage: image-privacy-scan.sh <image> | --archive <saved tar> | --classify-paths' >&2; exit 2 ;;
 *) WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
    docker save "$1" -o "$WORK/image.tar"; ARCHIVE="$WORK/image.tar"; shift ;;
esac
python3 "$ROOT/tools/artifact-privacy-scan.py" --image-archive "$ARCHIVE" --classifications "$ROOT/tools/image-privacy-classifications.json" "$@"
