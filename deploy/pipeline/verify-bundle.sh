#!/usr/bin/env bash
# Verify a pipeline artifact's SSH signature AND its exact bytes.
#
#   deploy/pipeline/verify-bundle.sh --file <artifact> --sig <artifact.sig> \
#       --allowed-signers <file> --identity <signer-id> [--sha256 <expected>] [--namespace ns]
#
# FAILS CLOSED: an unverifiable signature, an unknown signer, a missing
# allowed_signers file, or a byte/sha256 mismatch all exit non-zero and
# print no "verified" line. Nothing downstream may run on a failure.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/pipeline-lib.sh"

FILE=""; SIG=""; ALLOWED=""; IDENTITY=""; EXPECT=""; NS="policyvault-pipeline"
while [ $# -gt 0 ]; do
  case "$1" in
    --file) FILE="$2"; shift 2;;
    --sig) SIG="$2"; shift 2;;
    --allowed-signers) ALLOWED="$2"; shift 2;;
    --identity) IDENTITY="$2"; shift 2;;
    --sha256) EXPECT="$2"; shift 2;;
    --namespace) NS="$2"; shift 2;;
    *) pv_die "unknown argument: $1";;
  esac
done
[ -n "$FILE" ] && [ -n "$ALLOWED" ] && [ -n "$IDENTITY" ] || pv_die "usage: verify-bundle.sh --file <artifact> [--sig <file.sig>] --allowed-signers <file> --identity <id> [--sha256 <expected>]"
pv_need ssh-keygen
[ -f "$FILE" ] || pv_die "no such artifact: $FILE"
[ -n "$SIG" ] || SIG="$FILE.sig"
[ -f "$SIG" ] || pv_die "no signature: $SIG"
[ -f "$ALLOWED" ] || pv_die "no allowed_signers file: $ALLOWED (never verify against an implicit key set)"

SHA="$(pv_sha256 "$FILE")"
if [ -n "$EXPECT" ] && [ "$SHA" != "$EXPECT" ]; then
  pv_die "ARTIFACT SHA256 MISMATCH: got $SHA expected $EXPECT"
fi
if ! ssh-keygen -Y verify -f "$ALLOWED" -I "$IDENTITY" -n "$NS" -s "$SIG" < "$FILE" >/dev/null 2>&1; then
  pv_die "SIGNATURE VERIFICATION FAILED for $FILE (identity $IDENTITY, namespace $NS)"
fi
pv_log "verified: $(basename "$FILE") signer=$IDENTITY sha256=$SHA"
printf '%s\n' "$SHA"
