#!/usr/bin/env bash
# END-TO-END LOCAL PROOF of the PolicyVault deployment pipeline
# (Track 8). NON-PRODUCTION ONLY: local docker, scratch directories,
# scratch tags/compose project, a TEST signing key generated into the
# scratch dir, testnet-10 + json persistence. It never reads a
# production env file, never contacts a droplet, never publishes
# anything, and never touches a production tag.
#
#   deploy/pipeline/local-proof.sh --workdir <scratch dir> [--repo <checkout>]
#
# Proves, in order:
#   P1 deterministic source bundle + SSH signature (and a tamper NEGATIVE)
#   P2 "builder" role: build from the VERIFIED bundle in a fresh context
#   P3 seed transfer (full) -> apply -> loaded image digest == built digest
#   P4 one-file change -> delta transfer bytes vs full image bytes
#   P5 verify-before-activate: privacy scan + private-container readiness
#   P6 activate by digest on a scratch compose stack, then ROLLBACK
#   P7 interrupted build leaves NO artifact; rerun is clean and identical
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/pipeline-lib.sh"

WORKDIR=""; REPO="$(cd "$HERE/../.." && pwd)"
while [ $# -gt 0 ]; do
  case "$1" in
    --workdir) WORKDIR="$2"; shift 2;;
    --repo) REPO="$2"; shift 2;;
    *) pv_die "unknown argument: $1";;
  esac
done
[ -n "$WORKDIR" ] || pv_die "usage: local-proof.sh --workdir <scratch dir> [--repo <checkout>]"
pv_need docker; pv_need ssh-keygen
mkdir -p "$WORKDIR"; WORKDIR="$(cd "$WORKDIR" && pwd)"
REPORT="$WORKDIR/proof-report.txt"
: > "$REPORT"
say() { printf '%s\n' "$*" | tee -a "$REPORT"; }
PROJECT=pv-t8-proof
CACHE="$WORKDIR/target-cache"        # stands in for the target's blob cache
ENVF="$WORKDIR/proof.env"
COMPOSE="$WORKDIR/docker-compose.proof.yml"
PORT=3399

say "=== PolicyVault deployment-pipeline LOCAL PROOF (non-production) ==="
say "repo    : $REPO"
say "workdir : $WORKDIR"
say "started : $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- P1: deterministic source bundle + signature ---------------------------
say ""; say "--- P1 source bundle + signature ---"
ssh-keygen -q -t ed25519 -N '' -C 'policyvault-t8-TEST-KEY (scratch only)' -f "$WORKDIR/test_key" <<< y >/dev/null 2>&1 || true
printf 'pv-test-builder %s\n' "$(cat "$WORKDIR/test_key.pub")" > "$WORKDIR/allowed_signers"
SRC_SHA="$("$HERE/bundle-source.sh" --repo "$REPO" --out "$WORKDIR/src-v1.tgz" --allow-dirty)"
"$HERE/sign-bundle.sh" --file "$WORKDIR/src-v1.tgz" --key "$WORKDIR/test_key"
"$HERE/verify-bundle.sh" --file "$WORKDIR/src-v1.tgz" --allowed-signers "$WORKDIR/allowed_signers" \
  --identity pv-test-builder --sha256 "$SRC_SHA" >/dev/null
say "bundle bytes    : $(stat -c '%s' "$WORKDIR/src-v1.tgz")  sha256 $SRC_SHA  SIGNATURE VERIFIED"
# NEGATIVE: one flipped byte must fail verification.
cp "$WORKDIR/src-v1.tgz" "$WORKDIR/tampered.tgz"; cp "$WORKDIR/src-v1.tgz.sig" "$WORKDIR/tampered.tgz.sig"
printf '\0' | dd of="$WORKDIR/tampered.tgz" bs=1 seek=1024 conv=notrunc status=none
if "$HERE/verify-bundle.sh" --file "$WORKDIR/tampered.tgz" --allowed-signers "$WORKDIR/allowed_signers" \
     --identity pv-test-builder >/dev/null 2>&1; then
  pv_die "P1 NEGATIVE FAILED: a tampered bundle verified"
fi
say "negative        : tampered bundle REJECTED (signature verification failed) OK"

# --- P2: build from the verified bundle in a fresh context -----------------
say ""; say "--- P2 build from the signed bundle (builder role, fresh context) ---"
BASE_DIGEST="$(docker image inspect ubuntu:26.04 --format '{{index .RepoDigests 0}}' 2>/dev/null || true)"
D1="$("$HERE/remote-build.sh" --bundle "$WORKDIR/src-v1.tgz" --vendor "$REPO/deploy/vendor" \
      --workdir "$WORKDIR" --out "$WORKDIR/img-v1.tar" \
      --allowed-signers "$WORKDIR/allowed_signers" --identity pv-test-builder --sha256 "$SRC_SHA" \
      ${BASE_DIGEST:+--base "$BASE_DIGEST"})"
IMG1_BYTES="$(stat -c '%s' "$WORKDIR/img-v1.tar")"
say "v1 image digest : $D1"
say "v1 archive bytes: $IMG1_BYTES  (base pin: ${BASE_DIGEST:-UNPINNED})"

# --- P3: seed transfer, apply, digest equality ----------------------------
say ""; say "--- P3 seed transfer -> apply -> digest equality ---"
rm -rf "$CACHE"; mkdir -p "$CACHE"
"$HERE/image-inventory.sh" --cache "$CACHE" --out "$WORKDIR/inv-0.txt"
"$HERE/pack-delta.sh" --image "$WORKDIR/img-v1.tar" --out "$WORKDIR/ship-seed.tar" \
  --inventory "$WORKDIR/inv-0.txt" --label "seed" >/dev/null
"$HERE/sign-bundle.sh" --file "$WORKDIR/ship-seed.tar" --key "$WORKDIR/test_key"
SEED_BYTES="$(stat -c '%s' "$WORKDIR/ship-seed.tar")"
rm -f "$WORKDIR/img-v1.tar"   # bytes recorded; the seed bundle carries everything
docker image rm -f "$D1" >/dev/null 2>&1 || true
LOADED1="$("$HERE/apply-delta.sh" --bundle "$WORKDIR/ship-seed.tar" --cache "$CACHE" \
  --allowed-signers "$WORKDIR/allowed_signers" --identity pv-test-builder \
  --expect-digest "$D1" --tag "policyvault-app:t8-proof-v1")"
[ "$LOADED1" = "$D1" ] || pv_die "P3 FAILED: loaded $LOADED1 != built $D1"
rm -f "$WORKDIR/ship-seed.tar" "$WORKDIR/ship-seed.tar.sig"   # sizes recorded; free the scratch
say "seed ship bytes : $SEED_BYTES"
say "loaded digest   : $LOADED1  == built digest OK"

# --- P4: one-file change -> delta ------------------------------------------
say ""; say "--- P4 one-web-file change -> delta transfer ---"
CHANGED_FILE="$REPO/web/app.js"
cp "$CHANGED_FILE" "$WORKDIR/app.js.orig"
restore_web() { cp "$WORKDIR/app.js.orig" "$CHANGED_FILE"; }
trap restore_web EXIT
printf '\n// t8 local proof: one-line change (reverted by the proof script)\n' >> "$CHANGED_FILE"
SRC2_SHA="$("$HERE/bundle-source.sh" --repo "$REPO" --out "$WORKDIR/src-v2.tgz" --allow-dirty)"
"$HERE/sign-bundle.sh" --file "$WORKDIR/src-v2.tgz" --key "$WORKDIR/test_key"
D2="$("$HERE/remote-build.sh" --bundle "$WORKDIR/src-v2.tgz" --vendor "$REPO/deploy/vendor" \
      --workdir "$WORKDIR" --out "$WORKDIR/img-v2.tar" \
      --allowed-signers "$WORKDIR/allowed_signers" --identity pv-test-builder --sha256 "$SRC2_SHA" \
      ${BASE_DIGEST:+--base "$BASE_DIGEST"})"
restore_web; trap - EXIT
"$HERE/image-inventory.sh" --cache "$CACHE" --out "$WORKDIR/inv-1.txt"
"$HERE/pack-delta.sh" --image "$WORKDIR/img-v2.tar" --out "$WORKDIR/ship-delta.tar" \
  --inventory "$WORKDIR/inv-1.txt" --label "one web file changed" >/dev/null
"$HERE/sign-bundle.sh" --file "$WORKDIR/ship-delta.tar" --key "$WORKDIR/test_key"
DELTA_BYTES="$(stat -c '%s' "$WORKDIR/ship-delta.tar")"
IMG2_BYTES="$(stat -c '%s' "$WORKDIR/img-v2.tar")"
LOADED2="$("$HERE/apply-delta.sh" --bundle "$WORKDIR/ship-delta.tar" --cache "$CACHE" \
  --allowed-signers "$WORKDIR/allowed_signers" --identity pv-test-builder \
  --expect-digest "$D2" --tag "policyvault-app:t8-proof-v2")"
[ "$LOADED2" = "$D2" ] || pv_die "P4 FAILED: loaded $LOADED2 != built $D2"
rm -f "$WORKDIR/img-v2.tar"   # size recorded above; free the scratch
say "v2 image digest : $D2"
say "v2 archive bytes: $IMG2_BYTES"
say "DELTA ship bytes: $DELTA_BYTES  ($(awk -v a="$DELTA_BYTES" -v b="$IMG2_BYTES" 'BEGIN{printf "%.2f%% of the full image; %.1fx less", 100*a/b, b/a}'))"
say "at 35 KB/s      : full $(awk -v b="$IMG2_BYTES" 'BEGIN{printf "%.2f h", b/35840/3600}')  vs delta $(awk -v b="$DELTA_BYTES" 'BEGIN{printf "%.1f s", b/35840}')"
say "loaded digest   : $LOADED2  == built digest OK"

# --- P5: verify before activate --------------------------------------------
say ""; say "--- P5 verify-before-activate (privacy scan + private readiness probe) ---"
V2_BUILD="$(docker image inspect "$D2" --format '{{range .Config.Env}}{{println .}}{{end}}' | awk -F= '$1=="POLICYVAULT_BUILD_ID"{print $2}')"
"$HERE/verify-before-activate.sh" --digest "$D2" --repo "$REPO" --expect-build-id "$V2_BUILD" >>"$REPORT" 2>&1 \
  || pv_die "P5 FAILED: verify-before-activate refused $D2"
say "verify-before-activate: PASS (buildId $V2_BUILD)"

# --- P6: activate by digest + rollback on a scratch compose stack ----------
say ""; say "--- P6 activate by digest, then rollback (scratch compose) ---"
V1_BUILD="$(docker image inspect "$D1" --format '{{range .Config.Env}}{{println .}}{{end}}' | awk -F= '$1=="POLICYVAULT_BUILD_ID"{print $2}')"
cat > "$ENVF" <<ENVEOF
# scratch proof env — NON-PRODUCTION (testnet-10, json persistence)
KASPA_NETWORK_ID=testnet-10
POLICYVAULT_PERSISTENCE=json
POLICYVAULT_BIND_ADDRESS=0.0.0.0
PV_PROOF_APP_TAG=t8-proof-v1
ENVEOF
cat > "$COMPOSE" <<COMPOSEEOF
name: $PROJECT
services:
  app:
    image: policyvault-app:\${PV_PROOF_APP_TAG:?}
    env_file: [proof.env]
    ports: [ "127.0.0.1:$PORT:3080" ]
    read_only: true
    tmpfs:
      - /tmp:size=64m,mode=1777
      - /app/data:size=64m,uid=10001,gid=10001,mode=0700
COMPOSEEOF
buildid_now() { curl -s -m 5 "http://127.0.0.1:$PORT/api/v1/health" | sed -n 's/.*"buildId": *"\([^"]*\)".*/\1/p'; }
wait_build() { for i in $(seq 1 20); do b="$(buildid_now || true)"; [ -n "$b" ] && { printf '%s' "$b"; return 0; }; sleep 1; done; return 1; }
docker compose -f "$COMPOSE" --env-file "$ENVF" up -d app >/dev/null 2>&1
B0="$(wait_build)" || pv_die "P6 FAILED: scratch stack never became live"
say "stack live on v1: buildId=$B0 (expected $V1_BUILD)"
[ "$B0" = "$V1_BUILD" ] || pv_die "P6 FAILED: expected $V1_BUILD, serving $B0"
"$HERE/deploy-by-digest.sh" --digest "$D2" --tag t8-proof-v2 --env "$ENVF" --compose "$COMPOSE" \
  --key PV_PROOF_APP_TAG --service app --apply >>"$REPORT" 2>&1 || pv_die "P6 FAILED: activation refused"
sleep 3; B1="$(wait_build)" || pv_die "P6 FAILED: no health after activation"
say "after activate  : buildId=$B1 (expected $V2_BUILD)"
[ "$B1" = "$V2_BUILD" ] || pv_die "P6 FAILED: activation did not take effect"
"$HERE/deploy-by-digest.sh" --rollback "$D1" --tag t8-proof-v1 --env "$ENVF" --compose "$COMPOSE" \
  --key PV_PROOF_APP_TAG --service app --apply >>"$REPORT" 2>&1 || pv_die "P6 FAILED: rollback refused"
sleep 3; B2="$(wait_build)" || pv_die "P6 FAILED: no health after rollback"
say "after rollback  : buildId=$B2 (expected $V1_BUILD)"
[ "$B2" = "$V1_BUILD" ] || pv_die "P6 FAILED: rollback did not take effect"
ENV_OTHER_CHANGED="$(diff <(grep -v '^PV_PROOF_APP_TAG=' "$ENVF") <(printf '%s\n' '# scratch proof env — NON-PRODUCTION (testnet-10, json persistence)' 'KASPA_NETWORK_ID=testnet-10' 'POLICYVAULT_PERSISTENCE=json' 'POLICYVAULT_BIND_ADDRESS=0.0.0.0') | grep -c '^[<>]' || true)"
say "env non-tag lines changed by two activations + one rollback: $ENV_OTHER_CHANGED (expected 0)"
[ "$ENV_OTHER_CHANGED" = "0" ] || pv_die "P6 FAILED: activation altered env values other than the tag key"
docker compose -f "$COMPOSE" --env-file "$ENVF" down >/dev/null 2>&1 || true

# --- P7: interrupted build safety ------------------------------------------
say ""; say "--- P7 interrupted build safety ---"
rm -f "$WORKDIR/img-kill.tar" "$WORKDIR"/img-kill.tar.partial.* 2>/dev/null || true
KILLED=0
for t in 5 3 2 1; do
  set +e
  timeout -s KILL "$t" "$HERE/build-image.sh" --context "$REPO" --out "$WORKDIR/img-kill.tar" \
    --build-id t8kill --epoch 1700000000 ${BASE_DIGEST:+--base "$BASE_DIGEST"} >/dev/null 2>&1
  KILL_RC=$?
  set -e
  if [ "$KILL_RC" != 0 ] && [ ! -f "$WORKDIR/img-kill.tar" ]; then KILLED=1; break; fi
  say "  (build finished within ${t}s — retrying the kill with a shorter deadline)"
  rm -f "$WORKDIR/img-kill.tar" "$WORKDIR/img-kill.tar.build.json"
done
[ "$KILLED" = 1 ] || pv_die "P7 INCONCLUSIVE: could not interrupt a build mid-flight"
say "killed build rc=$KILL_RC : final artifact ABSENT OK (only the atomic rename can produce it)"
# NOTE: the `docker build` CLI is a CHILD of the killed wrapper and can
# outlive it, still writing ITS OWN temp path. That is harmless by
# construction — nothing but a completed run performs the atomic rename,
# so an orphan can never publish an artifact — and the next run purges
# stale partials. Proven deterministically here with a planted stale
# partial rather than by racing the orphan:
STALE="$WORKDIR/img-kill.tar.partial.999999"
head -c 4096 /dev/zero > "$STALE"
D3="$("$HERE/build-image.sh" --context "$REPO" --out "$WORKDIR/img-kill.tar" \
      --build-id t8kill --epoch 1700000000 ${BASE_DIGEST:+--base "$BASE_DIGEST"})"
D3_FROM_ARCHIVE="$(bash -c '. "'"$HERE"'/pipeline-lib.sh"; pv_oci_image_digest "'"$WORKDIR"'/img-kill.tar"')"
[ "$D3_FROM_ARCHIVE" = "$D3" ] || pv_die "P7 FAILED: rerun artifact does not resolve to the reported digest"
[ ! -f "$STALE" ] || pv_die "P7 FAILED: a planted stale partial survived the next build"
say "rerun after kill: complete artifact, digest $D3 (re-derived from the file: MATCH)"
say "planted stale partial (4096 B) purged by the next build: OK"
rm -f "$WORKDIR/img-kill.tar" "$WORKDIR/img-kill.tar.build.json"

say ""; say "=== ALL PROOFS PASSED ($(date -u +%Y-%m-%dT%H:%M:%SZ)) ==="
say "report: $REPORT"
