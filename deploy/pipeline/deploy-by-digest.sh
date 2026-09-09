#!/usr/bin/env bash
# Activate (or roll back to) an EXACT image digest.
#
#   deploy/pipeline/deploy-by-digest.sh --digest sha256:... --tag <tagname> \
#       --env <env-file> [--compose <file>] [--service app] [--apply]
#   deploy/pipeline/deploy-by-digest.sh --rollback sha256:... --tag <tagname> --env <env-file> [--apply]
#
# Contract:
#   - the digest MUST already be present locally (never pulls, never
#     builds, never resolves a floating tag);
#   - the tag is (re)bound to that digest and re-resolved as proof;
#   - EXACTLY ONE line of the env file changes — the image-tag key. Every
#     other value, comment, blank line, and the file mode are preserved
#     byte for byte (diffed and asserted before the rename);
#   - the env file is rewritten via temp + atomic rename, so an
#     interruption leaves either the old file or the new one, never a
#     truncated one;
#   - the activation is appended to a durable ledger next to the env file
#     (previous digest recorded; image switch only — database/schema recovery is separate);
#   - without --apply nothing is restarted: the exact compose command is
#     printed for the operator.
#
# PRODUCTION IS OWNER-GATED: pointing this at a mainnet env file requires
# PV_PIPELINE_ALLOW_PRODUCTION_ENV=1 in the environment, and that is an
# owner decision, not a pipeline default.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/pipeline-lib.sh"

DIGEST=""; ROLLBACK=""; TAG=""; ENVF=""; COMPOSE=""; SERVICE="app"; APPLY=0; KEY="PV_PROD_APP_TAG"; IMAGE_REPO="policyvault-app"
while [ $# -gt 0 ]; do
  case "$1" in
    --digest) DIGEST="$2"; shift 2;;
    --rollback) ROLLBACK="$2"; shift 2;;
    --tag) TAG="$2"; shift 2;;
    --env) ENVF="$2"; shift 2;;
    --compose) COMPOSE="$2"; shift 2;;
    --service) SERVICE="$2"; shift 2;;
    --key) KEY="$2"; shift 2;;
    --image-repo) IMAGE_REPO="$2"; shift 2;;
    --apply) APPLY=1; shift;;
    *) pv_die "unknown argument: $1";;
  esac
done
if [ -n "$ROLLBACK" ]; then DIGEST="$ROLLBACK"; fi
[ -n "$DIGEST" ] && [ -n "$TAG" ] && [ -n "$ENVF" ] \
  || pv_die "usage: deploy-by-digest.sh (--digest|--rollback) sha256:... --tag <tagname> --env <env-file> [--compose f] [--service app] [--apply]"
pv_require_digest_format "$DIGEST"
pv_need docker
[ -f "$ENVF" ] || pv_die "no such env file: $ENVF"
case "$TAG" in *:*|*/*) pv_die "--tag takes a bare tag name (e.g. fullscale-rc10), not a repo/tag reference";; esac

# Production guard (fail closed).
if grep -qE '^POLICYVAULT_ALLOW_MAINNET=1|^KASPA_NETWORK_ID=mainnet' "$ENVF"; then
  [ "${PV_PIPELINE_ALLOW_PRODUCTION_ENV:-0}" = "1" ] \
    || pv_die "REFUSING: $ENVF is a MAINNET/production env. Activating production is an explicit owner-gated action (set PV_PIPELINE_ALLOW_PRODUCTION_ENV=1 only under that authorization)."
  pv_log "PRODUCTION ENV ACKNOWLEDGED via PV_PIPELINE_ALLOW_PRODUCTION_ENV=1"
fi

# 1. the digest must be here already.
LOADED="$(docker image inspect "$DIGEST" --format '{{.Id}}' 2>/dev/null || true)"
[ "$LOADED" = "$DIGEST" ] || pv_die "image $DIGEST is not present locally (docker reports '$LOADED') — apply the delta first; this script never pulls or builds"

# 2. bind the tag and prove the binding.
docker tag "$DIGEST" "$IMAGE_REPO:$TAG"
RESOLVED="$(docker image inspect "$IMAGE_REPO:$TAG" --format '{{.Id}}')"
[ "$RESOLVED" = "$DIGEST" ] || pv_die "tag $IMAGE_REPO:$TAG resolves to $RESOLVED, not $DIGEST"
pv_log "tag bound: $IMAGE_REPO:$TAG -> $DIGEST"

# 3. single-key atomic env rewrite.
grep -qE "^${KEY}=" "$ENVF" || pv_die "env file has no ${KEY}= line — refusing to invent one"
PREV_TAG="$(awk -F= -v k="$KEY" '$1==k{sub(/^[^=]*=/,"");print}' "$ENVF")"
PREV_DIGEST="$(docker image inspect "$IMAGE_REPO:$PREV_TAG" --format '{{.Id}}' 2>/dev/null || echo "unknown")"
ENVDIR="$(cd "$(dirname "$ENVF")" && pwd)"
TMP="$ENVDIR/.$(basename "$ENVF").pipeline.$$"
trap 'rm -f "$TMP"' EXIT
awk -v k="$KEY" -v v="$TAG" 'BEGIN{FS=OFS="="} $1==k{print k "=" v; next} {print}' "$ENVF" > "$TMP"
# Assert EXACTLY the one line differs.
CHANGED="$(diff <(cat "$ENVF") <(cat "$TMP") | grep -c '^[<>]' || true)"
if [ "$PREV_TAG" = "$TAG" ]; then
  [ "$CHANGED" = "0" ] || pv_die "unexpected env diff while re-activating the same tag ($CHANGED changed lines)"
  pv_log "env already selects $KEY=$TAG (no change)"
else
  [ "$CHANGED" = "2" ] || pv_die "REFUSING: env rewrite would change $CHANGED lines, expected exactly 1 (2 diff lines)"
fi
pv_atomic_install "$TMP" "$ENVF"; trap - EXIT
pv_log "env updated: $KEY: ${PREV_TAG:-<empty>} -> $TAG ($ENVF)"

# 4. durable activation ledger (append-only, next to the env file).
LEDGER="$ENVDIR/pv-activation-ledger.jsonl"
printf '{"ts":"%s","action":"%s","key":"%s","previous_tag":"%s","previous_digest":"%s","new_tag":"%s","new_digest":"%s","applied":%s}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([ -n "$ROLLBACK" ] && echo rollback || echo activate)" \
  "$KEY" "$PREV_TAG" "$PREV_DIGEST" "$TAG" "$DIGEST" "$([ "$APPLY" = 1 ] && echo true || echo false)" >> "$LEDGER"
pv_log "ledger: $LEDGER"
if [ "$PREV_DIGEST" != "unknown" ]; then
  pv_log "RECOVERY LIMIT: the command below switches only the image. It does not restore or migrate the database. Verify target-schema compatibility and preservation of all newer writes/claims before use; otherwise repair forward."
  pv_log "CONDITIONAL IMAGE SWITCH: $0 --rollback $PREV_DIGEST --tag $PREV_TAG --env $ENVF ${COMPOSE:+--compose $COMPOSE} --apply"
fi

# 5. restart (explicit).
CMD="docker compose${COMPOSE:+ -f $COMPOSE} --env-file $ENVF up -d $SERVICE"
if [ "$APPLY" = 1 ]; then
  [ -n "$COMPOSE" ] || pv_die "--apply needs --compose <file>"
  pv_log "running: $CMD"
  # shellcheck disable=SC2086
  docker compose -f "$COMPOSE" --env-file "$ENVF" up -d "$SERVICE" >&2
  pv_log "service $SERVICE now runs $(docker compose -f "$COMPOSE" --env-file "$ENVF" images "$SERVICE" 2>/dev/null | tail -1)"
else
  pv_log "DRY RUN — nothing restarted. To activate run:"
  printf '%s\n' "$CMD"
fi
printf '%s\n' "$DIGEST"
