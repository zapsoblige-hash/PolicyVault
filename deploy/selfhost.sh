#!/bin/bash
# PolicyVault one-command self-hosting.
#
#   bash deploy/selfhost.sh init [--mainnet] [--rpc-url ws://...] [--origin URL] [--port N]
#   bash deploy/selfhost.sh up | check | acceptance | status | logs
#   bash deploy/selfhost.sh upgrade | rollback | backup | restore FILE | down | destroy
#
# Equal-security self-hosting: same image, same fail-closed configuration
# matrix, same server keylessness as the hosted deployment. This script
# never handles wallet keys or seed phrases — they must not exist here.
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$DEPLOY_DIR")"
ENV_FILE="$DEPLOY_DIR/selfhost.env"
STATE_FILE="$DEPLOY_DIR/.selfhost-state"
COMPOSE=(docker compose -f "$DEPLOY_DIR/docker-compose.selfhost.yml" --env-file "$ENV_FILE" --project-directory "$DEPLOY_DIR")

die()  { echo "selfhost: ERROR: $*" >&2; exit 1; }
note() { echo "selfhost: $*"; }

need_env() { [ -f "$ENV_FILE" ] || die "no $ENV_FILE — run: bash deploy/selfhost.sh init"; }
env_get()  { grep -E "^$1=" "$ENV_FILE" | head -1 | cut -d= -f2-; }

build_id() { git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo "selfhost"; }

cmd_init() {
  local network="testnet-10" rpc_url="" origin="" port="3080" mainnet=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --mainnet) mainnet=1; network="mainnet"; shift ;;
      --rpc-url) rpc_url="$2"; shift 2 ;;
      --origin)  origin="$2"; shift 2 ;;
      --port)    port="$2"; shift 2 ;;
      *) die "unknown init option: $1" ;;
    esac
  done
  [ -f "$ENV_FILE" ] && die "$ENV_FILE already exists — refusing to overwrite (delete it first if you mean it)"
  command -v openssl >/dev/null || die "openssl is required to generate secrets"
  if docker volume inspect policyvault-selfhost_pv-selfhost-pgdata >/dev/null 2>&1; then
    die "database volume policyvault-selfhost_pv-selfhost-pgdata already exists — its password will not match a freshly generated one. Run 'bash deploy/selfhost.sh destroy' first (DELETES data), or restore your previous selfhost.env"
  fi

  if [ "$mainnet" = 1 ]; then
    [ -n "$rpc_url" ] || die "--mainnet requires --rpc-url ws://<YOUR-OWN-TRUSTED-mainnet-kaspad>:18110 (never a public node)"
    case "${origin:-https://}" in http://*) die "--mainnet requires an https:// --origin (Secure cookies cannot ride plaintext HTTP; the insecure-cookie override is testnet/local only)";; esac
    echo "!! MAINNET: real KAS. The config written here carries the same dual"
    echo "!! unlock the hosted production uses (POLICYVAULT_ALLOW_MAINNET +"
    echo "!! explicit RPC URL). Your node must be YOUR OWN trusted kaspad"
    echo "!! with --utxoindex. Type MAINNET to continue:"
    read -r confirm
    [ "$confirm" = "MAINNET" ] || die "mainnet not confirmed"
  else
    rpc_url="${rpc_url:-ws://host-kaspad:18210}"
  fi
  origin="${origin:-http://127.0.0.1:$port}"

  local pg_pass; pg_pass="$(openssl rand -hex 24)"
  umask 177
  if [ "$mainnet" = 1 ]; then
    # MAINNET: the config gate refuses POLICYVAULT_PG_NO_TLS (fail closed),
    # so the TLS-less bundled postgres container cannot be used. You must
    # bring a TLS-capable PostgreSQL (managed, or your own with certs).
    cat > "$ENV_FILE" <<EOF
# PolicyVault self-host environment (MAINNET) — GENERATED $(date -u +%Y-%m-%dT%H:%M:%SZ), mode 600.
# NEVER commit this file. NEVER put wallet keys or seed phrases here —
# the application must not possess them (server wallet custody = NONE).
KASPA_NETWORK_ID=mainnet
KASPA_RPC_URL=$rpc_url
POLICYVAULT_ALLOW_MAINNET=true
POLICYVAULT_BUILD_ID=$(build_id)
PV_SELFHOST_APP_TAG=selfhost-$(build_id)
PV_SELFHOST_HTTP_PORT=$port
PV_SELFHOST_POSTGRES_IMAGE=postgres:16-alpine
POLICYVAULT_PERSISTENCE=postgres
# MAINNET requires an EXTERNAL TLS-capable PostgreSQL (the app refuses
# no-TLS postgres on mainnet, by design). Fill these in:
POLICYVAULT_PG_HOST=REPLACE_WITH_TLS_PG_HOST
POLICYVAULT_PG_PORT=5432
POLICYVAULT_PG_USER=REPLACE
POLICYVAULT_PG_PASSWORD=REPLACE
POLICYVAULT_PG_DATABASE=policyvault_selfhost
# compose variables kept for the unused bundled postgres definition:
PV_SELFHOST_PG_USER=unused
PV_SELFHOST_PG_PASSWORD=$pg_pass
PV_SELFHOST_PG_DATABASE=unused
POLICYVAULT_HOSTED_AUTH=1
POLICYVAULT_APP_ORIGIN=$origin
# Set ONLY if you front the app with a reverse proxy that overwrites the
# client-IP header on every request (see docs/selfhost-quickstart.md):
# POLICYVAULT_TRUSTED_PROXY_HEADER=x-real-ip
# ---- explicitly NOT set (each would weaken or fake the deployment) ----
# POLICYVAULT_DEV_SIGNER    — never in a reachable service
# POLICYVAULT_LEGACY_CREATE — never
# PV_TEST_CRASH_AT          — never
# POLICYVAULT_STAGING_BANNER — this is a real deployment, not staging
EOF
    note "wrote $ENV_FILE (mode 600), network=mainnet, buildId=$(build_id)"
    note "MAINNET: fill in the REPLACE PostgreSQL values (TLS-capable PG"
    note "required — the app fails closed on no-TLS postgres on mainnet),"
    note "then: bash deploy/selfhost.sh up"
    return 0
  fi
  cat > "$ENV_FILE" <<EOF
# PolicyVault self-host environment — GENERATED $(date -u +%Y-%m-%dT%H:%M:%SZ), mode 600.
# NEVER commit this file. NEVER put wallet keys or seed phrases here —
# the application must not possess them (server wallet custody = NONE).
KASPA_NETWORK_ID=$network
KASPA_RPC_URL=$rpc_url
# POLICYVAULT_ALLOW_MAINNET — unset: mainnet impossible with this config
POLICYVAULT_BUILD_ID=$(build_id)
PV_SELFHOST_APP_TAG=selfhost-$(build_id)
PV_SELFHOST_HTTP_PORT=$port
PV_SELFHOST_POSTGRES_IMAGE=postgres:16-alpine
POLICYVAULT_PERSISTENCE=postgres
POLICYVAULT_PG_HOST=postgres
POLICYVAULT_PG_PORT=5432
POLICYVAULT_PG_USER=pvselfhost
POLICYVAULT_PG_PASSWORD=$pg_pass
POLICYVAULT_PG_DATABASE=policyvault_selfhost
# Compose-private PG has no TLS certificates; this override is scoped to
# the compose-internal network (the DB is never published anywhere) and
# is refused by the app on mainnet.
POLICYVAULT_PG_NO_TLS=1
PV_SELFHOST_PG_USER=pvselfhost
PV_SELFHOST_PG_PASSWORD=$pg_pass
PV_SELFHOST_PG_DATABASE=policyvault_selfhost
POLICYVAULT_HOSTED_AUTH=1
POLICYVAULT_APP_ORIGIN=$origin
$( case "$origin" in http://*) printf '%s\n' \
"# Loopback/plaintext origin: Secure cookies cannot ride plain HTTP, so" \
"# hosted auth requires this explicit override — LOCAL/TESTNET TESTING" \
"# ONLY (the app refuses it in a mainnet config; remove it and switch" \
"# POLICYVAULT_APP_ORIGIN to https:// when you front this with TLS):" \
"POLICYVAULT_AUTH_COOKIE_INSECURE=1";; esac )
# Set ONLY if you front the app with a reverse proxy that overwrites the
# client-IP header on every request (see docs/selfhost-quickstart.md):
# POLICYVAULT_TRUSTED_PROXY_HEADER=x-real-ip
# ---- explicitly NOT set (each would weaken or fake the deployment) ----
# POLICYVAULT_DEV_SIGNER    — never in a reachable service
# POLICYVAULT_LEGACY_CREATE — never
# PV_TEST_CRASH_AT          — never
# POLICYVAULT_STAGING_BANNER — this is a real deployment, not staging
EOF
  note "wrote $ENV_FILE (mode 600), network=$network, buildId=$(build_id)"
  note "next: bash deploy/selfhost.sh up"
}

cmd_up() {
  need_env
  local tag; tag="$(env_get PV_SELFHOST_APP_TAG)"
  grep -qE "^POLICYVAULT_PG_(HOST|USER|PASSWORD)=REPLACE" "$ENV_FILE" \
    && die "PostgreSQL placeholders in $ENV_FILE are unfilled — failing closed"
  if [ ! -f "$DEPLOY_DIR/vendor/bin/silverc" ] || [ ! -d "$DEPLOY_DIR/vendor/kaspa" ]; then
    note "deploy/vendor incomplete — staging the pinned runtime toolchain (tools/stage-vendor.sh)..."
    bash "$REPO_DIR/tools/stage-vendor.sh" \
      || die "stage-vendor failed — it needs sibling silverscript + rusty-kaspa checkouts and the pre-fetched Node dist (see the script header and docs/selfhost-quickstart.md)"
  fi
  [ -f "$DEPLOY_DIR/vendor/dist/node-v20.20.2-linux-x64.tar.xz" ] \
    || die "deploy/vendor/dist is missing the pinned Node dist — pre-fetch it per the stage-vendor.sh header (SHASUMS256-verified)"
  note "building image policyvault-app:$tag from this source tree..."
  "${COMPOSE[@]}" build app
  if grep -q "^POLICYVAULT_ALLOW_MAINNET=true" "$ENV_FILE"; then
    # Mainnet: external TLS PostgreSQL; the bundled container stays down.
    note "running one-shot schema migration (external TLS PostgreSQL)..."
    "${COMPOSE[@]}" run --rm --no-deps migrate
    note "starting app (no bundled postgres on mainnet)..."
    "${COMPOSE[@]}" up -d --no-deps app
  else
    note "starting postgres..."
    "${COMPOSE[@]}" up -d postgres
    note "running one-shot schema migration..."
    "${COMPOSE[@]}" run --rm migrate
    note "starting app..."
    "${COMPOSE[@]}" up -d app
  fi
  note "started. Run: bash deploy/selfhost.sh check"
}

cmd_check() {
  need_env
  local port network build ok=0 fail=0
  port="$(env_get PV_SELFHOST_HTTP_PORT)"; port="${port:-3080}"
  network="$(env_get KASPA_NETWORK_ID)"
  build="$(env_get POLICYVAULT_BUILD_ID)"
  local base="http://127.0.0.1:$port"

  chk() { if [ "$2" = "$3" ]; then echo "PASS  $1 ($3)"; ok=$((ok+1)); else echo "FAIL  $1 — expected $2, got $3"; fail=$((fail+1)); fi }

  local health ready net
  health=$(curl -sf --max-time 10 "$base/api/v1/health") || die "health unreachable at $base — is the app running? (selfhost.sh status/logs)"
  ready=$(curl -sf --max-time 10 "$base/api/v1/health/ready") || die "readiness unreachable"

  chk "health.ok"            "true"      "$(echo "$health" | python3 -c 'import json,sys;print(str(json.load(sys.stdin)["ok"]).lower())')"
  chk "health.networkId"     "$network"  "$(echo "$health" | python3 -c 'import json,sys;print(json.load(sys.stdin)["networkId"])')"
  chk "health.buildId"       "$build"    "$(echo "$health" | python3 -c 'import json,sys;print(json.load(sys.stdin)["buildId"])')"
  chk "ready.ready"          "true"      "$(echo "$ready" | python3 -c 'import json,sys;print(str(json.load(sys.stdin)["ready"]).lower())')"
  chk "ready.persistence"    "postgres"  "$(echo "$ready" | python3 -c 'import json,sys;print(json.load(sys.stdin)["persistence"])')"

  if net=$(curl -sf --max-time 15 "$base/api/v1/network/status"); then
    chk "network.networkId"    "$network"  "$(echo "$net" | python3 -c 'import json,sys;print(json.load(sys.stdin)["networkId"])')"
    chk "network.isSynced"     "true"      "$(echo "$net" | python3 -c 'import json,sys;print(str(json.load(sys.stdin)["isSynced"]).lower())')"
    chk "network.hasUtxoIndex" "true"      "$(echo "$net" | python3 -c 'import json,sys;print(str(json.load(sys.stdin)["hasUtxoIndex"]).lower())')"
  else
    echo "FAIL  network.status — kaspad unreachable at $(env_get KASPA_RPC_URL). Your node must be running with --utxoindex and forwarded to the compose network (node tools/staging-kaspad-proxy.js). Live operations FAIL CLOSED until this passes."
    fail=$((fail+3))
  fi

  # posture: dev/test flags must be absent from the running config
  for bad in POLICYVAULT_DEV_SIGNER POLICYVAULT_LEGACY_CREATE PV_TEST_CRASH_AT POLICYVAULT_STAGING_BANNER; do
    if grep -qE "^$bad=" "$ENV_FILE"; then echo "FAIL  posture: $bad is set"; fail=$((fail+1)); else echo "PASS  posture: $bad absent"; ok=$((ok+1)); fi
  done
  # custody: no wallet-secret-shaped variables may exist
  if grep -vE "^#" "$ENV_FILE" | grep -qiE "seed|mnemonic|private_key|wallet_secret"; then
    echo "FAIL  custody: wallet-secret-shaped variable present in env"; fail=$((fail+1))
  else
    echo "PASS  custody: no wallet secret of any role exists in this deployment (by design)"; ok=$((ok+1))
  fi

  echo
  echo "$ok checks passed, $fail failed."
  echo "Covenant identity: regenerate + compare with 'OUT=/tmp/pv.sil node tools/gen_v4_1.js && cmp /tmp/pv.sil contracts/PolicyVault.v0.4.1.sil'."
  echo "Deeper posture run: bash deploy/selfhost.sh acceptance"
  [ $fail -eq 0 ]
}

cmd_acceptance() {
  need_env
  local port network build
  port="$(env_get PV_SELFHOST_HTTP_PORT)"; port="${port:-3080}"
  network="$(env_get KASPA_NETWORK_ID)"
  build="$(env_get POLICYVAULT_BUILD_ID)"
  note "running the full externally-driven acceptance suite against 127.0.0.1:$port ..."
  node "$REPO_DIR/tools/prod-acceptance.js" "http://127.0.0.1:$port" --network "$network" --expect-build "$build"
}

cmd_upgrade() {
  need_env
  local old new
  old="$(env_get PV_SELFHOST_APP_TAG)"
  new="selfhost-$(build_id)"
  [ "$old" = "$new" ] && die "source tree is at the same build ($new) — nothing to upgrade to. Pull/checkout the new source first."
  echo "PREVIOUS_TAG=$old" > "$STATE_FILE"
  sed -i -e "s/^PV_SELFHOST_APP_TAG=.*/PV_SELFHOST_APP_TAG=$new/" -e "s/^POLICYVAULT_BUILD_ID=.*/POLICYVAULT_BUILD_ID=$(build_id)/" "$ENV_FILE"
  note "upgrading $old -> $new (previous tag recorded for rollback)"
  cmd_up
}

cmd_rollback() {
  need_env
  [ -f "$STATE_FILE" ] || die "no recorded previous tag ($STATE_FILE missing)"
  local prev; prev="$(grep '^PREVIOUS_TAG=' "$STATE_FILE" | cut -d= -f2)"
  [ -n "$prev" ] || die "no PREVIOUS_TAG recorded"
  note "rolling back app tag to $prev (NOTE: schema migrations are NOT rolled back automatically —"
  note "a newer schema than the app expects will fail closed; restore a backup if you migrated)"
  sed -i "s/^PV_SELFHOST_APP_TAG=.*/PV_SELFHOST_APP_TAG=$prev/" "$ENV_FILE"
  "${COMPOSE[@]}" up -d app
  note "rolled back. Run: bash deploy/selfhost.sh check"
}

cmd_backup() {
  need_env
  local out="$DEPLOY_DIR/selfhost-backup-$(date -u +%Y%m%d-%H%M%S).dump"
  umask 177
  "${COMPOSE[@]}" exec -T postgres pg_dump -Fc -U "$(env_get PV_SELFHOST_PG_USER)" "$(env_get PV_SELFHOST_PG_DATABASE)" > "$out"
  note "backup written: $out ($(wc -c < "$out") bytes, mode 600). Store it encrypted, off-host."
}

cmd_restore() {
  need_env
  local file="${1:-}"; [ -f "$file" ] || die "usage: selfhost.sh restore <backup.dump>"
  echo "Restoring OVERWRITES the current database. Type RESTORE to continue:"
  read -r confirm; [ "$confirm" = "RESTORE" ] || die "not confirmed"
  "${COMPOSE[@]}" stop app
  "${COMPOSE[@]}" exec -T postgres pg_restore --clean --if-exists -U "$(env_get PV_SELFHOST_PG_USER)" -d "$(env_get PV_SELFHOST_PG_DATABASE)" < "$file"
  "${COMPOSE[@]}" up -d app
  note "restored from $file. Run: bash deploy/selfhost.sh check"
}

cmd_down()    { need_env; "${COMPOSE[@]}" down; note "stopped (data volume kept)."; }
cmd_destroy() {
  need_env
  echo "This DELETES the database volume and generated config. Type DESTROY to continue:"
  read -r confirm; [ "$confirm" = "DESTROY" ] || die "not confirmed"
  "${COMPOSE[@]}" down -v
  rm -f "$ENV_FILE" "$STATE_FILE"
  note "destroyed (images kept; remove with 'docker rmi' if desired)."
}
cmd_status()  { need_env; "${COMPOSE[@]}" ps; }
cmd_logs()    { need_env; "${COMPOSE[@]}" logs --tail 100 app; }

case "${1:-}" in
  init)       shift; cmd_init "$@" ;;
  up)         cmd_up ;;
  check)      cmd_check ;;
  acceptance) cmd_acceptance ;;
  upgrade)    cmd_upgrade ;;
  rollback)   cmd_rollback ;;
  backup)     cmd_backup ;;
  restore)    shift; cmd_restore "$@" ;;
  status)     cmd_status ;;
  logs)       cmd_logs ;;
  down)       cmd_down ;;
  destroy)    cmd_destroy ;;
  *) sed -n '2,8p' "${BASH_SOURCE[0]}"; exit 2 ;;
esac
