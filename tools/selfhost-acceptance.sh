#!/usr/bin/env bash
# Automated self-hosting acceptance: exercises the documented one-command
# self-hosting path (deploy/selfhost.sh + docs/selfhost-quickstart.md) from
# a CLEAN `git archive` copy of the current checkout — the same tree shape
# an outside self-hoster gets — and prints a PASS/FAIL matrix.
#
# Idempotent and self-cleaning: every container/volume/network/image it
# creates is named with the PV_ACCEPT_PREFIX prefix (default
# "pvselfhost-acceptance"; override via env, e.g. for a throwaway retest
# lane) and is removed on exit, success or failure. It NEVER touches this
# checkout's own deploy/selfhost.env, deploy/*.dump, or any already-running
# self-hosted stack — everything happens inside a throwaway `git archive`
# copy under a scratch directory.
#
# What this does NOT do (documented, not a gap in this tool):
#   - It does not build the covenant VM toolchain (tests/vm) or fetch the
#     pinned Node dist from the network. It requires deploy/vendor/ to
#     already be staged in THIS checkout (tools/stage-vendor.sh) and
#     copies it into the throwaway tree. If deploy/vendor/ is missing, the
#     VENDOR step is reported REQUIREMENT_NOT_AVAILABLE and the run stops
#     — this is a prerequisite-staging concern, not something an
#     acceptance re-run should silently redo on every invocation.
#   - It does not drive a real browser/KasWare wallet. The auth surfaces
#     it proves are: the challenge endpoint is reachable and validates
#     input, and (via `selfhost.sh acceptance`) a full real-Schnorr
#     sign-in using a throwaway generated test keypair. End-to-end KasWare
#     browser sign-in stays NOT-TESTED-HEADLESS by design.
#
# Usage:
#   bash tools/selfhost-acceptance.sh
#   PV_ACCEPT_PREFIX=pvselfhost-t10 bash tools/selfhost-acceptance.sh
#   TMPDIR=/path/with/space bash tools/selfhost-acceptance.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${PV_ACCEPT_PREFIX:-pvselfhost-acceptance}"
PORT="${PV_ACCEPT_PORT:-3082}"
WORKDIR=""
PROXY_PID=""
RESULTS=()   # "STEP<TAB>RESULT<TAB>detail"
FAIL_COUNT=0

pass() { RESULTS+=("$1	PASS	${2:-}"); echo "PASS  $1 ${2:-}"; }
fail() { RESULTS+=("$1	FAIL	${2:-}"); echo "FAIL  $1 ${2:-}"; FAIL_COUNT=$((FAIL_COUNT+1)); }
skip() { RESULTS+=("$1	SKIP	${2:-}"); echo "SKIP  $1 ${2:-}"; }
note() { echo "selfhost-acceptance: $*"; }

COMPOSE_PROJECT_NAME="$PREFIX"
export COMPOSE_PROJECT_NAME

compose() {
  docker compose -f "$WORKDIR/deploy/docker-compose.selfhost.yml" \
    --env-file "$WORKDIR/deploy/selfhost.env" \
    --project-directory "$WORKDIR/deploy" "$@"
}

# Snapshot every policyvault-app:* image tag that exists BEFORE this run
# does anything, so cleanup can remove exactly the ones this run created —
# by set difference, not by guessing a naming pattern. This matters
# because `deploy/selfhost.sh upgrade` always retags to its own
# "selfhost-<buildId>" scheme regardless of the prefix this run started
# with, so a prefix-only cleanup regex would miss upgrade-created images
# (and, worse, a broader pattern could risk deleting an unrelated
# concurrent session's image of the same shape). Never touches any image
# that already existed before this run started.
IMAGES_BEFORE="$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep '^policyvault-app:' || true)"

cleanup() {
  set +e
  if [ -n "$PROXY_PID" ]; then kill "$PROXY_PID" >/dev/null 2>&1; fi
  if [ -n "$WORKDIR" ] && [ -f "$WORKDIR/deploy/selfhost.env" ]; then
    compose down -v >/dev/null 2>&1
  fi
  local images_after new_images
  images_after="$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep '^policyvault-app:' || true)"
  new_images="$(comm -13 <(echo "$IMAGES_BEFORE" | sort) <(echo "$images_after" | sort))"
  if [ -n "$new_images" ]; then
    echo "$new_images" | xargs -r docker rmi >/dev/null 2>&1
  fi
  if [ -n "$WORKDIR" ]; then rm -rf "$WORKDIR"; fi
  note "cleanup complete (containers/volumes/networks removed; images removed: $(echo "$new_images" | tr '\n' ' '); $WORKDIR removed)"
}
trap cleanup EXIT

json_get() { python3 -c "import json,sys;d=json.load(sys.stdin);print(d$1)" 2>/dev/null; }

# ---------------------------------------------------------------- 1. CLEAN COPY
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/${PREFIX}.XXXXXX")"
note "workdir: $WORKDIR"
if (cd "$REPO_ROOT" && git archive HEAD) | tar -x -C "$WORKDIR" 2>/tmp/pvacc-archive.err; then
  if [ -d "$WORKDIR/.git" ] || [ -d "$WORKDIR/data" ] && find "$WORKDIR/data" -mindepth 1 2>/dev/null | grep -q .; then
    # .git must never appear; a tracked-but-empty data/ dir is fine.
    if [ -d "$WORKDIR/.git" ]; then fail "CLEAN_COPY" "git archive leaked .git"; else pass "CLEAN_COPY" "(tracked data/ evidence files present, as committed — no .git, no node_modules)"; fi
  else
    pass "CLEAN_COPY" "$(cd "$WORKDIR" && find . -maxdepth 1 | wc -l) top-level entries, no .git"
  fi
else
  fail "CLEAN_COPY" "git archive HEAD failed: $(cat /tmp/pvacc-archive.err 2>/dev/null)"
  exit 1
fi

# ---------------------------------------------------------------- 2. VENDOR
if [ -f "$REPO_ROOT/deploy/vendor/bin/silverc" ] && [ -d "$REPO_ROOT/deploy/vendor/kaspa" ] \
   && [ -f "$REPO_ROOT/deploy/vendor/bin/pv_call_encoder" ] && [ -f "$REPO_ROOT/deploy/vendor/bin/pv_vm_preflight" ] \
   && [ -f "$REPO_ROOT/deploy/vendor/bin/pv_tx_probe" ] && [ -f "$REPO_ROOT/deploy/vendor/dist/node-v20.20.2-linux-x64.tar.xz" ] \
   && [ -f "$REPO_ROOT/deploy/vendor/dist/node-SHASUMS256.txt" ]; then
  mkdir -p "$WORKDIR/deploy/vendor"
  cp -r "$REPO_ROOT/deploy/vendor/." "$WORKDIR/deploy/vendor/"
  pass "VENDOR" "reused already-staged $REPO_ROOT/deploy/vendor"
else
  skip "VENDOR" "REQUIREMENT_NOT_AVAILABLE — $REPO_ROOT/deploy/vendor is not fully staged; run tools/stage-vendor.sh (see docs/selfhost-quickstart.md Prerequisites) once, then re-run this acceptance script"
  note "stopping here — every later step needs the built image (partial run, not a failure)"
  echo
  echo "=== selfhost acceptance matrix ($PREFIX) — PARTIAL, stopped at VENDOR ==="
  printf '%-28s %-6s %s\n' "STEP" "RESULT" "DETAIL"
  for r in "${RESULTS[@]}"; do IFS=$'\t' read -r step res detail <<<"$r"; printf '%-28s %-6s %s\n' "$step" "$res" "$detail"; done
  exit 0
fi

# ---------------------------------------------------------------- 3. INIT
cd "$WORKDIR"
if bash deploy/selfhost.sh init --port "$PORT" >/tmp/pvacc-init.log 2>&1; then
  perm="$(stat -c '%a' deploy/selfhost.env 2>/dev/null)"
  if [ "$perm" = "600" ]; then pass "INIT" "selfhost.env mode 600"; else fail "INIT" "selfhost.env mode $perm (expected 600)"; fi
else
  fail "INIT" "$(tail -3 /tmp/pvacc-init.log)"; cat_matrix_and_exit=1
fi
sed -i "s/^PV_SELFHOST_APP_TAG=.*/PV_SELFHOST_APP_TAG=${PREFIX}/" deploy/selfhost.env

# ---------------------------------------------------------------- 4. MISSING-ENV FAILURE MESSAGE
mv deploy/selfhost.env /tmp/pvacc-env.bak
out="$(bash deploy/selfhost.sh check 2>&1 || true)"
mv /tmp/pvacc-env.bak deploy/selfhost.env
if echo "$out" | grep -q "run: bash deploy/selfhost.sh init"; then
  pass "FAILURE_MISSING_ENV" "clear actionable message"
else
  fail "FAILURE_MISSING_ENV" "unclear message: $out"
fi

# ---------------------------------------------------------------- 5. UP
if bash deploy/selfhost.sh up >/tmp/pvacc-up.log 2>&1; then
  pass "UP" "image built, postgres+migrate+app started"
else
  fail "UP" "$(tail -15 /tmp/pvacc-up.log)"
fi
sleep 2

# ---------------------------------------------------------------- 6/7. HEALTH / READY
health="$(curl -sf --max-time 10 "http://127.0.0.1:$PORT/api/v1/health" 2>/dev/null)"
if [ -n "$health" ] && [ "$(echo "$health" | json_get '["ok"]')" = "True" ]; then
  pass "HEALTH" "ok=true buildId=$(echo "$health" | json_get '["buildId"]')"
else
  fail "HEALTH" "unreachable or ok!=true: $health"
fi
ready="$(curl -sf --max-time 10 "http://127.0.0.1:$PORT/api/v1/health/ready" 2>/dev/null)"
if [ -n "$ready" ] && [ "$(echo "$ready" | json_get '["ready"]')" = "True" ]; then
  pass "READY" "persistence=$(echo "$ready" | json_get '["persistence"]')"
else
  fail "READY" "unreachable or ready!=true: $ready"
fi

# ---------------------------------------------------------------- 8. NETWORK: absent node fails closed (bounded)
t0=$(date +%s)
curl -s --max-time 40 "http://127.0.0.1:$PORT/api/v1/network/status" >/tmp/pvacc-net-absent.txt 2>&1
t1=$(date +%s)
if [ ! -s /tmp/pvacc-net-absent.txt ] || ! grep -q '"isSynced"' /tmp/pvacc-net-absent.txt; then
  pass "NETWORK_ABSENT_NODE" "no fabricated success within $((t1-t0))s (kaspad forwarder not yet started)"
else
  fail "NETWORK_ABSENT_NODE" "returned success data with no node reachable: $(cat /tmp/pvacc-net-absent.txt)"
fi

# ---------------------------------------------------------------- 9. NETWORK: real node via the documented forwarder
BRIDGE_IP="$(docker exec "${COMPOSE_PROJECT_NAME}-app-1" getent hosts host-kaspad 2>/dev/null | awk '{print $1}')"
if [ -n "$BRIDGE_IP" ]; then
  node "$REPO_ROOT/tools/staging-kaspad-proxy.js" "$BRIDGE_IP" >/tmp/pvacc-proxy.log 2>&1 &
  PROXY_PID=$!
  sleep 1
  net="$(curl -sf --max-time 20 "http://127.0.0.1:$PORT/api/v1/network/status" 2>/dev/null)"
  if [ -n "$net" ] && [ "$(echo "$net" | json_get '["isSynced"]')" = "True" ] && [ "$(echo "$net" | json_get '["hasUtxoIndex"]')" = "True" ]; then
    pass "NETWORK_STATUS" "networkId=$(echo "$net" | json_get '["networkId"]') isSynced=true hasUtxoIndex=true"
  else
    fail "NETWORK_STATUS" "forwarder up but node status not verified: $net"
  fi
else
  skip "NETWORK_STATUS" "could not resolve host-kaspad inside the app container"
fi

# ---------------------------------------------------------------- 10. POSTURE CHECK
if out="$(bash deploy/selfhost.sh check 2>&1)"; then
  n="$(echo "$out" | grep -oE '^[0-9]+ checks passed, 0 failed\.$' || true)"
  if [ -n "$n" ]; then pass "POSTURE_CHECK" "$n"; else fail "POSTURE_CHECK" "unexpected output: $(echo "$out" | tail -3)"; fi
else
  fail "POSTURE_CHECK" "$(echo "$out" | tail -5)"
fi

# ---------------------------------------------------------------- 11. FULL ACCEPTANCE SUITE (incl. real Schnorr auth)
if out="$(bash deploy/selfhost.sh acceptance 2>&1)"; then
  summary="$(echo "$out" | grep -oE '^[0-9]+/[0-9]+ checks passed$' || true)"
  bad="$(echo "$out" | grep -c '^FAIL' || true)"
  if [ -n "$summary" ] && [ "$bad" = "0" ]; then
    pass "PROD_ACCEPTANCE_SUITE" "$summary (real Schnorr sign-in with a throwaway test keypair, tenancy, rate limits, CSP, host gate)"
  else
    fail "PROD_ACCEPTANCE_SUITE" "$summary bad=$bad"
  fi
else
  fail "PROD_ACCEPTANCE_SUITE" "$(echo "$out" | tail -10)"
fi

# ---------------------------------------------------------------- 12. AUTH CHALLENGE ENDPOINT REACHABLE
authresp="$(curl -s --max-time 10 -X POST "http://127.0.0.1:$PORT/api/v1/auth/challenge" \
  -H "Content-Type: application/json" -H "Origin: http://127.0.0.1:$PORT" \
  -d '{"walletAddress":"kaspatest:not-a-real-address"}' 2>/dev/null)"
if echo "$authresp" | grep -q '"code"'; then
  pass "AUTH_CHALLENGE_ENDPOINT" "reachable, validates input: $(echo "$authresp" | json_get '["error"]["code"]')"
else
  fail "AUTH_CHALLENGE_ENDPOINT" "no structured response: $authresp"
fi
note "full interactive KasWare browser sign-in is NOT-TESTED-HEADLESS by design (needs a real browser + extension)"

# ---------------------------------------------------------------- 13. BACKUP
if bash deploy/selfhost.sh backup >/tmp/pvacc-backup.log 2>&1; then
  DUMP="$(ls -t deploy/selfhost-backup-*.dump 2>/dev/null | head -1)"
  perm="$(stat -c '%a' "$DUMP" 2>/dev/null)"
  if [ -n "$DUMP" ] && [ "$perm" = "600" ] && [ -s "$DUMP" ]; then
    pass "BACKUP" "$(basename "$DUMP") $(wc -c <"$DUMP") bytes, mode 600"
  else
    fail "BACKUP" "dump missing or wrong mode ($perm)"
  fi
else
  fail "BACKUP" "$(tail -5 /tmp/pvacc-backup.log)"
fi

# ---------------------------------------------------------------- 14. RESTORE INTO A FRESH ISOLATED DB
if [ -n "${DUMP:-}" ]; then
  compose exec -T postgres createdb -U pvselfhost "pv_${PREFIX//-/_}_restorecheck" >/dev/null 2>&1
  if compose exec -T postgres pg_restore --no-owner --no-privileges -U pvselfhost -d "pv_${PREFIX//-/_}_restorecheck" < "$DUMP" >/tmp/pvacc-restorefresh.log 2>&1; then
    rows="$(compose exec -T postgres psql -tA -U pvselfhost -d "pv_${PREFIX//-/_}_restorecheck" -c "select count(*) from schema_migrations;" 2>/dev/null | tr -d '[:space:]')"
    stamp="$(compose exec -T postgres psql -tA -U pvselfhost -d "pv_${PREFIX//-/_}_restorecheck" -c "select value from pv_meta where key='network';" 2>/dev/null | tr -d '[:space:]\r')"
    compose exec -T postgres dropdb -U pvselfhost "pv_${PREFIX//-/_}_restorecheck" >/dev/null 2>&1
    if [ "$rows" = "9" ] && [ "$stamp" = "testnet-10" ]; then
      pass "RESTORE_FRESH_DB" "9 migrations, network stamp testnet-10, isolated DB never touched the live one"
    else
      fail "RESTORE_FRESH_DB" "rows=$rows stamp=$stamp"
    fi
  else
    fail "RESTORE_FRESH_DB" "$(tail -5 /tmp/pvacc-restorefresh.log)"
  fi
else
  skip "RESTORE_FRESH_DB" "no backup available"
fi

# ---------------------------------------------------------------- 15. RESTORE IN PLACE (documented Day-2 op)
if [ -n "${DUMP:-}" ]; then
  if echo RESTORE | bash deploy/selfhost.sh restore "$DUMP" >/tmp/pvacc-restore.log 2>&1; then
    sleep 2
    r2="$(curl -sf --max-time 10 "http://127.0.0.1:$PORT/api/v1/health/ready" 2>/dev/null)"
    if [ "$(echo "$r2" | json_get '["ready"]')" = "True" ]; then
      pass "RESTORE_IN_PLACE" "app healthy after restore"
    else
      fail "RESTORE_IN_PLACE" "not ready after restore: $r2"
    fi
  else
    fail "RESTORE_IN_PLACE" "$(tail -10 /tmp/pvacc-restore.log)"
  fi
else
  skip "RESTORE_IN_PLACE" "no backup available"
fi

# ---------------------------------------------------------------- 16. BAD PG CREDENTIAL FAILS CLOSED
cp deploy/selfhost.env /tmp/pvacc-env.saved
sed -i 's/^POLICYVAULT_PG_PASSWORD=.*/POLICYVAULT_PG_PASSWORD=wrong-acceptance-probe/' deploy/selfhost.env
compose up -d --no-deps app >/dev/null 2>&1
sleep 3
badlog="$(compose logs --tail 10 app 2>&1)"
cp /tmp/pvacc-env.saved deploy/selfhost.env
compose up -d --no-deps app >/dev/null 2>&1
sleep 3
if echo "$badlog" | grep -q "fail closed"; then
  pass "FAILURE_BAD_PG_CREDENTIAL" "clear fail-closed startup message, no data served"
else
  fail "FAILURE_BAD_PG_CREDENTIAL" "no clear fail-closed message: $(echo "$badlog" | tail -3)"
fi

# ---------------------------------------------------------------- 17. UPGRADE (content-addressed buildId, git-less tree)
echo "// selfhost-acceptance probe $(date -u)" >> server/src/server.js
old_tag="$(grep '^PV_SELFHOST_APP_TAG=' deploy/selfhost.env | cut -d= -f2)"
if out="$(bash deploy/selfhost.sh upgrade 2>&1)"; then
  new_tag="$(grep '^PV_SELFHOST_APP_TAG=' deploy/selfhost.env | cut -d= -f2)"
  if [ "$new_tag" != "$old_tag" ]; then
    pass "UPGRADE" "$old_tag -> $new_tag (content-hash buildId changed on a real source edit, no .git in this tree)"
  else
    fail "UPGRADE" "tag did not change: $out"
  fi
else
  fail "UPGRADE" "$(echo "$out" | tail -5)"
fi

# ---------------------------------------------------------------- 18. ROLLBACK (served buildId matches the restored image)
prev_build_id="$(grep '^PREVIOUS_BUILD_ID=' deploy/.selfhost-state 2>/dev/null | cut -d= -f2)"
if bash deploy/selfhost.sh rollback >/tmp/pvacc-rollback.log 2>&1; then
  sleep 2
  h="$(curl -sf --max-time 10 "http://127.0.0.1:$PORT/api/v1/health" 2>/dev/null)"
  served="$(echo "$h" | json_get '["buildId"]')"
  if [ -n "$prev_build_id" ] && [ "$served" = "$prev_build_id" ]; then
    pass "ROLLBACK" "served buildId ($served) matches the rolled-back image, not the upgraded one"
  else
    fail "ROLLBACK" "served=$served expected=$prev_build_id"
  fi
else
  fail "ROLLBACK" "$(tail -10 /tmp/pvacc-rollback.log)"
fi

# ---------------------------------------------------------------- 19. LOG REDACTION
pgpass="$(grep '^PV_SELFHOST_PG_PASSWORD=' deploy/selfhost.env | cut -d= -f2)"
alllogs="$(compose logs 2>&1)"
if echo "$alllogs" | grep -inE "seed|mnemonic|private[_ ]?key|$pgpass|wrong-acceptance-probe|BEGIN (RSA|EC|OPENSSH)" | grep -vq "startup failed"; then
  fail "LOG_REDACTION" "possible secret-shaped content in logs"
elif echo "$alllogs" | grep -qi "$pgpass"; then
  fail "LOG_REDACTION" "PG password literal found in logs"
else
  pass "LOG_REDACTION" "no seed/mnemonic/private-key/password patterns in app+postgres logs"
fi

# ---------------------------------------------------------------- 20. HOST REBOOT SIMULATION (docker restart)
compose restart >/tmp/pvacc-restart.log 2>&1
sleep 5
r3="$(curl -sf --max-time 15 "http://127.0.0.1:$PORT/api/v1/health/ready" 2>/dev/null)"
if [ "$(echo "$r3" | json_get '["ready"]')" = "True" ]; then
  pass "HOST_REBOOT_SIMULATION" "readiness returns after docker restart of the whole stack"
else
  fail "HOST_REBOOT_SIMULATION" "not ready after restart: $r3"
fi

# ---------------------------------------------------------------- 21. HIDDEN DEPENDENCY SCAN (self-host path only)
# PUBLIC BUILD: the operator-machine markers this scan looks for are supplied
# by the operator, never hardcoded. Default = generic home-directory, private
# RFC1918 and operator-account shapes. Override PV_SELFHOST_FORBIDDEN_RE to add
# your own machine's hostnames, IP addresses or usernames.
FORBIDDEN_RE="${PV_SELFHOST_FORBIDDEN_RE:-/home/[a-z][-a-z0-9_]*|/Users/[a-z][-a-z0-9_]*|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|pv_prod_ops|pv-ops@}"
hits="$(grep -rnE "$FORBIDDEN_RE" \
  "$WORKDIR/deploy/selfhost.sh" "$WORKDIR/deploy/docker-compose.selfhost.yml" \
  "$WORKDIR/tools/stage-vendor.sh" "$WORKDIR/tools/staging-kaspad-proxy.js" \
  "$WORKDIR/docs/selfhost-quickstart.md" 2>/dev/null || true)"
if [ -z "$hits" ]; then
  pass "HIDDEN_DEPENDENCY_SCAN" "no operator-machine-specific host/path/IP in the self-hosting path files"
else
  fail "HIDDEN_DEPENDENCY_SCAN" "$hits"
fi

# ---------------------------------------------------------------- 22. DESTROY
if echo DESTROY | bash deploy/selfhost.sh destroy >/tmp/pvacc-destroy.log 2>&1; then
  if [ ! -f deploy/selfhost.env ] && ! docker volume ls --format '{{.Name}}' | grep -q "^${PREFIX}_pv-selfhost-pgdata$"; then
    pass "DESTROY" "env + volume removed"
  else
    fail "DESTROY" "residual state after destroy"
  fi
else
  fail "DESTROY" "$(tail -10 /tmp/pvacc-destroy.log)"
fi

# ---------------------------------------------------------------- matrix + exit
echo
echo "=== selfhost acceptance matrix ($PREFIX) ==="
printf '%-28s %-6s %s\n' "STEP" "RESULT" "DETAIL"
for r in "${RESULTS[@]}"; do IFS=$'\t' read -r step res detail <<<"$r"; printf '%-28s %-6s %s\n' "$step" "$res" "$detail"; done
echo
echo "$((${#RESULTS[@]} - FAIL_COUNT))/${#RESULTS[@]} passed (excluding SKIPs counted as neither)."
[ "$FAIL_COUNT" -eq 0 ]
