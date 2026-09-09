#!/usr/bin/env bash
# Deterministic PolicyVault SOURCE BUNDLE (build input for a remote
# builder; also the provenance record of any pipeline build).
#
#   deploy/pipeline/bundle-source.sh --repo <dir> --out <bundle.tgz> [--allow-dirty]
#
# Properties:
#   - contains ONLY the runtime paths the container image already ships
#     (the Dockerfile COPY set) — never notes, directives, evidence,
#     env files, keys, data roots, .git, or the private history; the
#     bundle is therefore no more disclosive than the image itself;
#   - byte-deterministic: file list from git, sorted, fixed mtime
#     (the HEAD commit time), uid/gid 0, pax headers stripped, gzip -n;
#   - carries SOURCE_IDENTITY (commit + tree hash + epoch) so a builder
#     with no git checkout still produces an identified, dated image;
#   - self-check: every COPY source in deploy/Dockerfile that is not a
#     staged vendor artifact MUST be covered by the include set — a new
#     COPY that nobody added here FAILS the bundle (fail closed);
#   - reuses tools/image-privacy-scan.sh --classify-paths as the
#     forbidden-path filter over the exact file list being bundled.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/pipeline-lib.sh"

REPO=""; OUT=""; ALLOW_DIRTY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --allow-dirty) ALLOW_DIRTY=1; shift;;
    *) pv_die "unknown argument: $1";;
  esac
done
[ -n "$REPO" ] && [ -n "$OUT" ] || pv_die "usage: bundle-source.sh --repo <dir> --out <bundle.tgz> [--allow-dirty]"
pv_need git; pv_need tar; pv_need gzip; pv_need sha256sum
REPO="$(cd "$REPO" && pwd)"
[ -f "$REPO/deploy/Dockerfile" ] || pv_die "not a PolicyVault checkout: $REPO"

# Runtime include set = the Dockerfile COPY sources (minus deploy/vendor,
# which is staged on the builder by tools/stage-vendor.sh) + the build
# recipe itself. Kept explicit so adding a path is a reviewed decision.
INCLUDE=(LICENSE NOTICE core sdk/src sdk/package.json sdk/package-lock.json
         server/src server/migrations server/package.json
         web contracts
         deploy/Dockerfile .dockerignore)
EXCLUDE=(':!core/**/test/**' ':!core/**/testutil/**' ':!core/crossruntime/**'
         ':!contracts/experiments/**' ':!**/*.env' ':!**/.env*')

# Fail closed if the Dockerfile COPYs something the include set misses.
while read -r src; do
  case "$src" in
    deploy/vendor/*|--from=*|"") continue;;
  esac
  covered=0
  for inc in "${INCLUDE[@]}"; do case "$src" in "$inc"|"$inc"/*) covered=1;; esac; done
  [ "$covered" = 1 ] || pv_die "deploy/Dockerfile COPYs '$src' which the source-bundle include set does not cover — update INCLUDE deliberately"
done < <(awk '/^COPY /{ if ($0 ~ /--from=/) next; for(i=2;i<NF;i++) if ($i !~ /^[-\/]/) print $i }' "$REPO/deploy/Dockerfile")

if [ "$ALLOW_DIRTY" = 0 ]; then
  [ -z "$(git -C "$REPO" status --porcelain -- "${INCLUDE[@]}")" ] \
    || pv_die "runtime source paths are dirty — commit first (or --allow-dirty for a local experiment)"
fi

COMMIT="$(git -C "$REPO" rev-parse HEAD)"
TREE="$(git -C "$REPO" rev-parse 'HEAD^{tree}')"
SHORT="$(git -C "$REPO" rev-parse --short HEAD)"
EPOCH="$(git -C "$REPO" log -1 --format=%ct)"

STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
FILES="$STAGE/files.txt"
( cd "$REPO" && git ls-files -- "${INCLUDE[@]}" "${EXCLUDE[@]}" ) | LC_ALL=C sort > "$FILES"
[ -s "$FILES" ] || pv_die "empty file list — refusing to bundle nothing"

# Privacy gate: the SAME forbidden-path classifier the image scan uses.
if ! "$REPO/tools/image-privacy-scan.sh" --classify-paths < "$FILES" >"$STAGE/privacy.out" 2>&1; then
  cat "$STAGE/privacy.out" >&2
  pv_die "SOURCE BUNDLE PRIVACY SCAN FAILED — forbidden paths in the file list"
fi

mkdir -p "$STAGE/src"
( cd "$REPO" && tar --files-from="$FILES" -cf - ) | tar -xf - -C "$STAGE/src"

# CONTENT ID: sha256 over "<file sha256>  <path>" for every bundled file.
# (The separator is "." — the server validates POLICYVAULT_BUILD_ID as
# 1..64 chars of [A-Za-z0-9._-] and fails closed on anything else.)
# It identifies the exact BYTES being built, independently of git state —
# so a --allow-dirty bundle can never claim the clean commit's identity
# (the build id becomes <short-commit>+<content-id prefix>).
( cd "$STAGE/src" && xargs -a "$FILES" -d '\n' sha256sum ) | LC_ALL=C sort -k2 > "$STAGE/content.txt"
CONTENT_ID="$(pv_sha256 "$STAGE/content.txt")"
BUILD_TAG="$SHORT"
if [ -n "$(git -C "$REPO" status --porcelain -- "${INCLUDE[@]}")" ]; then
  BUILD_TAG="$SHORT.${CONTENT_ID:0:8}"
  pv_log "WARNING: bundling a MODIFIED tree — build identity is $BUILD_TAG (never the bare commit)"
fi
cat > "$STAGE/src/SOURCE_IDENTITY" <<IDENT
schema=policyvault.source-bundle/1
commit=$COMMIT
short_commit=$BUILD_TAG
tree=$TREE
content_id=$CONTENT_ID
epoch=$EPOCH
files=$(wc -l < "$FILES")
IDENT

pv_tar_deterministic "$STAGE/src" "$STAGE/bundle.tar" "$EPOCH"
gzip -9n -c "$STAGE/bundle.tar" > "$STAGE/bundle.tgz"

OUT_DIR="$(cd "$(dirname "$OUT")" && pwd)"; OUT="$OUT_DIR/$(basename "$OUT")"
pv_atomic_install "$STAGE/bundle.tgz" "$OUT"
SHA="$(pv_sha256 "$OUT")"; BYTES="$(stat -c '%s' "$OUT")"
cat > "$OUT.json" <<JSON
{
  "artifact": "policyvault-source-bundle",
  "schema": "policyvault.source-bundle/1",
  "commit": "$COMMIT",
  "tree": "$TREE",
  "short_commit": "$BUILD_TAG",
  "content_id": "$CONTENT_ID",
  "source_date_epoch": $EPOCH,
  "files": $(wc -l < "$FILES"),
  "raw_tar_bytes": $(stat -c '%s' "$STAGE/bundle.tar"),
  "bundle_bytes": $BYTES,
  "bundle_sha256": "$SHA"
}
JSON
pv_log "source bundle: $OUT ($BYTES bytes, sha256 $SHA, identity $BUILD_TAG, $(wc -l < "$FILES") files)"
printf '%s\n' "$SHA"
