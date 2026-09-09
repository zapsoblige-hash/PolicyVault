#!/usr/bin/env bash
# tools/verify-image-vendor-pins.sh — FAIL-CLOSED verification that a built
# PolicyVault application image ships EXACTLY the vendored consensus-facing
# binaries the source tree pins (rc11 internal security review F-07: the rc11
# candidate packet recorded the image digest but not the vendored pv_* pins,
# so a substituted encoder / VM preflight / probe binary would have passed
# the packet's own verification).
#
#   tools/verify-image-vendor-pins.sh <image-ref> [pins-file]
#
# pins-file defaults to deploy/vendor-pins.sha256 (relative paths under
# deploy/vendor/). All six pinned native/WASM files MUST exist in the image at the
# Dockerfile's destination path with a byte-identical SHA-256; any missing
# entry, any mismatch, or any tool error exits non-zero. Never prints
# secrets; reads only the image filesystem.
set -euo pipefail

IMAGE="${1:?usage: $0 <image-ref> [pins-file]}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# rc12 review R-06: the default pins file is the TRACKED, reviewed
# deploy/vendor-pins.sha256 (never the machine-local, gitignored staging
# inventory). deploy/vendor/SHA256SUMS.txt may be passed explicitly; the
# sdk test vendor-pins-tracked.test.js requires the two to agree.
PINS="${2:-$ROOT/deploy/vendor-pins.sha256}"
[ -r "$PINS" ] || { echo "FAIL: pins file not readable: $PINS" >&2; exit 2; }

# destination map — must mirror deploy/Dockerfile COPY lines exactly
dest_of() {
  case "$1" in
    bin/pv_call_encoder)  echo /app/tests/vm/target/debug/pv_call_encoder ;;
    bin/pv_vm_preflight)  echo /app/tests/vm/target/debug/pv_vm_preflight ;;
    bin/pv_tx_probe)      echo /app/tests/vm/target/debug/pv_tx_probe ;;
    bin/silverc)          echo /home/pv/silverscript/target/debug/silverc ;;
    kaspa/kaspa.js)       echo /home/pv/rusty-kaspa/wasm/nodejs/kaspa/kaspa.js ;;
    kaspa/kaspa_bg.wasm)  echo /home/pv/rusty-kaspa/wasm/nodejs/kaspa/kaspa_bg.wasm ;;
    *) return 1 ;;
  esac
}

declare -a PATHS=() EXPECTED=() NAMES=()
while read -r sum rel; do
  [ -n "$sum" ] || continue
  case "$rel" in bin/*|kaspa/kaspa.js|kaspa/kaspa_bg.wasm) ;; *) continue ;; esac
  d="$(dest_of "$rel")" || { echo "FAIL: no image destination known for pinned binary $rel — update dest_of() together with deploy/Dockerfile" >&2; exit 3; }
  PATHS+=("$d"); EXPECTED+=("$sum"); NAMES+=("$rel")
done < "$PINS"
[ "${#PATHS[@]}" -eq 6 ] || { echo "FAIL: expected exactly 6 pinned native/WASM runtime files in $PINS, found ${#PATHS[@]}" >&2; exit 3; }

# one container invocation; sha256sum exits non-zero if any path is missing
if ! OUT="$(docker run --rm --entrypoint sha256sum "$IMAGE" "${PATHS[@]}" 2>&1)"; then
  echo "FAIL: sha256sum inside $IMAGE failed:" >&2; echo "$OUT" >&2; exit 4
fi

status=0
for i in "${!PATHS[@]}"; do
  actual="$(printf '%s\n' "$OUT" | awk -v p="${PATHS[$i]}" '$2==p {print $1}')"
  if [ -z "$actual" ]; then echo "FAIL ${NAMES[$i]}: not present at ${PATHS[$i]}"; status=1
  elif [ "$actual" != "${EXPECTED[$i]}" ]; then echo "FAIL ${NAMES[$i]}: image ${actual} != pinned ${EXPECTED[$i]}"; status=1
  else echo "OK   ${NAMES[$i]}  ${actual}"; fi
done
[ "$status" -eq 0 ] && echo "VENDOR PINS VERIFIED: ${#PATHS[@]}/${#PATHS[@]} byte-identical in $IMAGE" || echo "VENDOR PIN VERIFICATION FAILED for $IMAGE" >&2
exit "$status"
