#!/usr/bin/env bash
# Sign a pipeline artifact with an SSH key (ssh-keygen -Y sign).
#
#   deploy/pipeline/sign-bundle.sh --file <artifact> --key <ssh-private-key> [--namespace <ns>]
#
# Established tooling only — no new crypto, no new dependency: OpenSSH's
# signature format, the same mechanism git commit signing uses. The
# signature covers the artifact BYTES; the verifier additionally pins the
# artifact sha256, so a signature can never be replayed onto other bytes.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/pipeline-lib.sh"

FILE=""; KEY=""; NS="policyvault-pipeline"
while [ $# -gt 0 ]; do
  case "$1" in
    --file) FILE="$2"; shift 2;;
    --key) KEY="$2"; shift 2;;
    --namespace) NS="$2"; shift 2;;
    *) pv_die "unknown argument: $1";;
  esac
done
[ -n "$FILE" ] && [ -n "$KEY" ] || pv_die "usage: sign-bundle.sh --file <artifact> --key <ssh-private-key> [--namespace ns]"
pv_need ssh-keygen
[ -f "$FILE" ] || pv_die "no such artifact: $FILE"
[ -f "$KEY" ] || pv_die "no such key: $KEY"

SHA="$(pv_sha256 "$FILE")"
ssh-keygen -Y sign -f "$KEY" -n "$NS" "$FILE" >/dev/null 2>&1 || pv_die "ssh-keygen -Y sign failed"
[ -f "$FILE.sig" ] || pv_die "signature not produced"
printf '%s  %s\n' "$SHA" "$(basename "$FILE")" > "$FILE.sha256"
pv_log "signed: $FILE.sig (namespace $NS, sha256 $SHA)"
