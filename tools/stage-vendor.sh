#!/usr/bin/env bash
# Stage only reviewed, privacy-safe runtime artifacts. Never overwrite a prior
# stage: choose a fresh output, verify it and explicitly promote it afterward.
# Build prerequisite: tools/build-private-safe-vendor.sh <fresh absolute dir>
# Usage: tools/stage-vendor.sh <artifact-dir> <fresh-stage-dir> [verified-node-dist-dir]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACTS="${1:?supply the output of tools/build-private-safe-vendor.sh}"
OUT="${2:?supply a fresh stage directory; preserve existing vendor evidence}"
DIST="${3:-$ROOT/deploy/vendor/dist}"
[ ! -e "$OUT" ] || { echo 'refusing existing stage output' >&2; exit 2; }
[ -d "$ARTIFACTS/bin" ] && [ -d "$ARTIFACTS/kaspa" ]
# Binary safe; remapping+stripping is not accepted merely by its name.
python3 "$ROOT/tools/artifact-privacy-scan.py" --tree "$ARTIFACTS/bin" > /dev/null
python3 "$ROOT/tools/artifact-privacy-scan.py" --tree "$ARTIFACTS/kaspa" > /dev/null
(cd "$ARTIFACTS" && sha256sum -c SHA256SUMS.txt >/dev/null)
for b in pv_call_encoder pv_vm_preflight pv_tx_probe silverc; do [ -x "$ARTIFACTS/bin/$b" ]; done
mkdir -p "$OUT"
cp -a "$ARTIFACTS/bin" "$ARTIFACTS/kaspa" "$OUT/"
[ -d "$DIST" ] && cp -a "$DIST" "$OUT/dist"
(cd "$OUT" && find bin kaspa dist -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt)
# The tracked pins, not this self-generated inventory, authorize image bytes.
(cd "$OUT" && sha256sum -c "$ROOT/deploy/vendor-pins.sha256")
echo 'STAGED — preserve this inventory and verify the resulting image independently'
