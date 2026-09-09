#!/usr/bin/env bash
# Apply a content-addressed image delta on the deployment target.
#
#   deploy/pipeline/apply-delta.sh --bundle <delta.tar> --cache <dir> \
#       [--sig <delta.tar.sig> --allowed-signers <f> --identity <id>] \
#       [--expect-digest sha256:...] [--tag <repo:tag>] [--no-load]
#
# Order is deliberate and fails closed at every step:
#   1. signature (when configured) BEFORE anything is unpacked;
#   2. every shipped blob must hash to its own name (else refuse);
#   3. blobs are installed into the cache atomically (temp + rename);
#   4. the FULL required blob set must be present in the cache;
#   5. the reassembled archive's image digest must equal the manifest's
#      digest AND --expect-digest;
#   6. only then `docker load`, and the loaded image ID must equal that
#      digest, or the load is treated as failed.
# Nothing here activates anything: deploy-by-digest.sh is a separate,
# explicit step.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/pipeline-lib.sh"

BUNDLE=""; CACHE=""; SIG=""; ALLOWED=""; IDENTITY=""; EXPECT=""; TAG=""; LOAD=1
while [ $# -gt 0 ]; do
  case "$1" in
    --bundle) BUNDLE="$2"; shift 2;;
    --cache) CACHE="$2"; shift 2;;
    --sig) SIG="$2"; shift 2;;
    --allowed-signers) ALLOWED="$2"; shift 2;;
    --identity) IDENTITY="$2"; shift 2;;
    --expect-digest) EXPECT="$2"; shift 2;;
    --tag) TAG="$2"; shift 2;;
    --no-load) LOAD=0; shift;;
    *) pv_die "unknown argument: $1";;
  esac
done
[ -n "$BUNDLE" ] && [ -n "$CACHE" ] || pv_die "usage: apply-delta.sh --bundle <delta.tar> --cache <dir> [--sig f --allowed-signers f --identity id] [--expect-digest sha256:..] [--tag repo:tag] [--no-load]"
pv_need tar; pv_need sha256sum
[ -f "$BUNDLE" ] || pv_die "no such bundle: $BUNDLE"

if [ -n "$ALLOWED" ] || [ -n "$SIG" ] || [ -n "$IDENTITY" ]; then
  [ -n "$ALLOWED" ] && [ -n "$IDENTITY" ] || pv_die "signature verification needs BOTH --allowed-signers and --identity"
  "$HERE/verify-bundle.sh" --file "$BUNDLE" ${SIG:+--sig "$SIG"} --allowed-signers "$ALLOWED" --identity "$IDENTITY" >/dev/null
else
  pv_log "WARNING: no --allowed-signers given — bundle authenticity is NOT verified (digest integrity still is)"
fi

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/x" "$CACHE/blobs/sha256"
tar -xf "$BUNDLE" -C "$WORK/x"
[ -f "$WORK/x/DELTA_MANIFEST" ] && [ -f "$WORK/x/REQUIRED_BLOBS" ] && [ -f "$WORK/x/index.json" ] \
  || pv_die "not a PolicyVault image delta (missing DELTA_MANIFEST/REQUIRED_BLOBS/index.json)"
MAN_DIGEST="$(awk -F= '$1=="image_digest"{print $2}' "$WORK/x/DELTA_MANIFEST")"
pv_require_digest_format "$MAN_DIGEST"
if [ -n "$EXPECT" ] && [ "$EXPECT" != "$MAN_DIGEST" ]; then
  pv_die "delta declares image $MAN_DIGEST but $EXPECT was expected"
fi

# 2+3: verify EVERY shipped blob FIRST, then install. Two passes on
# purpose: a bundle that fails integrity anywhere installs NOTHING, so a
# rejected transfer can never leave the target's cache half-populated.
if [ -d "$WORK/x/blobs/sha256" ]; then
  while IFS= read -r f; do
    name="$(basename "$f")"
    actual="$(pv_sha256 "$f")"
    [ "$actual" = "$name" ] || pv_die "BLOB INTEGRITY FAILURE: $name hashes to $actual (nothing installed)"
  done < <(find "$WORK/x/blobs/sha256" -maxdepth 1 -type f)
fi
installed=0
if [ -d "$WORK/x/blobs/sha256" ]; then
  while IFS= read -r f; do
    name="$(basename "$f")"
    if [ ! -f "$CACHE/blobs/sha256/$name" ]; then
      cp "$f" "$CACHE/blobs/sha256/.$name.partial.$$"
      mv -f "$CACHE/blobs/sha256/.$name.partial.$$" "$CACHE/blobs/sha256/$name"
      installed=$((installed+1))
    fi
  done < <(find "$WORK/x/blobs/sha256" -maxdepth 1 -type f)
fi
rm -rf "$WORK/x/blobs"   # installed and content-verified; the copies are dead weight
pv_log "blobs verified and installed: $installed"

# 4: full required set must be present.
missing=0
mkdir -p "$WORK/asm/blobs/sha256"
while read -r name bytes; do
  src="$CACHE/blobs/sha256/$name"
  if [ ! -f "$src" ]; then pv_log "MISSING required blob: $name ($bytes bytes)"; missing=$((missing+1)); continue; fi
  ln "$src" "$WORK/asm/blobs/sha256/$name" 2>/dev/null || cp "$src" "$WORK/asm/blobs/sha256/$name"
done < "$WORK/x/REQUIRED_BLOBS"
[ "$missing" = 0 ] || pv_die "$missing required blob(s) missing — the target inventory used to pack this delta is stale; re-pack with a fresh inventory"

cp "$WORK/x/index.json" "$WORK/asm/index.json"
if [ -f "$WORK/x/oci-layout" ]; then cp "$WORK/x/oci-layout" "$WORK/asm/oci-layout"; fi

if [ "$LOAD" = 0 ]; then
  # 5 (offline mode): materialise the archive and prove it resolves to the
  # declared digest without touching docker.
  pv_tar_deterministic "$WORK/asm" "$WORK/image.tar" 0
  ASM_DIGEST="$(pv_oci_image_digest "$WORK/image.tar")"
  [ "$ASM_DIGEST" = "$MAN_DIGEST" ] || pv_die "REASSEMBLY DIGEST MISMATCH: got $ASM_DIGEST expected $MAN_DIGEST"
  pv_log "reassembled archive digest: $ASM_DIGEST (matches manifest); --no-load: stopping before docker load"
  printf '%s\n' "$ASM_DIGEST"; exit 0
fi

# 5+6: stream the reassembled archive straight into `docker load` (never a
# second full-size temp file), then prove the loaded image IS the expected
# digest — a wrong or incomplete assembly cannot produce it.
pv_need docker
pv_tar_deterministic "$WORK/asm" - 0 | docker load >&2
LOADED="$(docker image inspect "$MAN_DIGEST" --format '{{.Id}}' 2>/dev/null || true)"
[ "$LOADED" = "$MAN_DIGEST" ] || pv_die "LOADED IMAGE IDENTITY MISMATCH: docker reports '$LOADED' for $MAN_DIGEST"
pv_log "loaded image id: $LOADED"
if [ -n "$TAG" ]; then
  docker tag "$MAN_DIGEST" "$TAG"
  RESOLVED="$(docker image inspect "$TAG" --format '{{.Id}}')"
  [ "$RESOLVED" = "$MAN_DIGEST" ] || pv_die "tag $TAG resolves to $RESOLVED, not $MAN_DIGEST"
  pv_log "tagged: $TAG -> $MAN_DIGEST"
fi
printf '%s\n' "$MAN_DIGEST"
