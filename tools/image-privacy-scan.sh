#!/usr/bin/env bash
# Automated container-image privacy/secret scan (Phase E, directive §8).
#
# Proves the built runtime image contains NONE of the private repository
# material — checking EVERY LAYER of the image (docker save), not just
# the final merged filesystem, so nothing can hide in an intermediate
# layer either.
#
# Usage: tools/image-privacy-scan.sh <image>          (e.g. policyvault-app:staging)
# Exit:  0 = clean; 1 = FORBIDDEN CONTENT FOUND; 2 = usage/environment error
set -euo pipefail

IMAGE="${1:?usage: image-privacy-scan.sh <image> | --classify-paths}"

# Path patterns that must appear in NO layer (private repo material,
# secrets, runtime data, credentials). Matched against tar member paths.
FORBIDDEN_PATHS='(^|/)\.git(/|$)|POLICYVAULT_CONTINUATION_NOTES|DIRECTIVE.*\.md|docs\.zip|(^|/)data(-mainnet)?/(vaults|requests|claims|receipts|audit|orgs)|(^|/)keys/|(^|/)wallets/|(^|/)secrets/|(^|/)backups/|\.env$|\.env\.|staging\.env$|id_rsa|id_ed25519|\.pem$|\.ppk$|cloudflared-.*\.json|(^|/)\.ssh(/|$)|(^|/)\.config/gh(/|$)|(^|/)\.aws(/|$)|(^|/)\.kube(/|$)'

# Content patterns that must appear in NO layer bytes (credential
# material classes; the deterministic TEST keys of the public test suite
# are not credentials and live under sdk/test which is not shipped).
FORBIDDEN_CONTENT='BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY|PV-CANARY-SECRET'

# Benign classes CLASSIFIED against the real Phase-E image (Phase E-R):
# textual collisions of the forbidden-path patterns with content every
# legitimate image of this Dockerfile must contain. Each exclusion is
# deliberately NARROW — anything not exactly matching these stays a
# failure (fail-closed):
#   1. the public CA trust store installed by ca-certificates in the
#      base stage (etc/ssl/certs/*.pem — PUBLIC root certificates, not
#      private keys; private-key MATERIAL is still caught by the
#      FORBIDDEN_CONTENT byte scan on every layer), plus OpenSSL's
#      usr/lib/ssl/cert.pem — verified IN the real image to be a
#      symlink to /etc/ssl/certs/ca-certificates.crt (the public
#      certificate bundle)
#   2. Ubuntu's stock EMPTY /var/backups directory entry (the bare
#      directory only — any FILE inside it still fails)
#   3. node_modules module directories literally named "keys/"
#      (es5-ext Array#keys/Object.keys shims etc.); these come from
#      `npm ci` against the committed lockfile in the deps stage, never
#      from repository files — a real keys/ dir anywhere else (app,
#      home, data roots) still fails
BENIGN_PATHS='^etc/ssl/certs/[^/]+\.pem$|^usr/lib/ssl/cert\.pem$|^var/backups/$|^app/sdk/node_modules/.+/keys/[^/]*$'

# --classify-paths: filter mode for the regression test (no docker):
# reads tar member paths on stdin, prints surviving violations, exit 1
# if any survive, 0 if none. Exercises EXACTLY the path logic the layer
# walk applies.
if [ "$IMAGE" = "--classify-paths" ]; then
  viol=$({ grep -E "$FORBIDDEN_PATHS" || true; } | { grep -Ev "$BENIGN_PATHS" || true; })
  if [ -n "$viol" ]; then
    echo "$viol"
    exit 1
  fi
  exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "saving image $IMAGE..."
docker save "$IMAGE" -o "$WORK/image.tar"
mkdir "$WORK/x"
tar -xf "$WORK/image.tar" -C "$WORK/x"

# Every layer blob (OCI layout: blobs/sha256/*, legacy: */layer.tar).
LAYERS=$(find "$WORK/x" -name "layer.tar" 2>/dev/null; find "$WORK/x/blobs" -type f 2>/dev/null || true)
[ -n "$LAYERS" ] || { echo "no layers found — unexpected image format"; exit 2; }

fail=0
for layer in $LAYERS; do
  # Skip non-tar blobs (json manifests/configs) silently.
  if ! tar -tf "$layer" >/dev/null 2>&1; then
    # config/manifest json: still scan its bytes for content patterns
    if grep -aEq "$FORBIDDEN_CONTENT" "$layer"; then
      echo "FORBIDDEN CONTENT in image metadata blob $layer"
      fail=1
    fi
    continue
  fi
  hits=$(tar -tf "$layer" | grep -E "$FORBIDDEN_PATHS" | grep -Ev "$BENIGN_PATHS" || true)
  if [ -n "$hits" ]; then
    echo "FORBIDDEN PATHS in layer $layer:"
    echo "$hits" | head -20
    fail=1
  fi
  # Content scan of the raw layer bytes (catches secrets inside files).
  if grep -aEq "$FORBIDDEN_CONTENT" "$layer"; then
    echo "FORBIDDEN CONTENT (private-key/canary material) in layer $layer"
    fail=1
  fi
done

# Positive checks: the things that MUST be present (sanity that we
# scanned the right image).
if ! tar -tf "$WORK/image.tar" >/dev/null 2>&1; then exit 2; fi
FOUND_APP=0
for layer in $LAYERS; do
  tar -tf "$layer" 2>/dev/null | grep -q "app/server/src/server.js" && FOUND_APP=1 && break || true
done
[ "$FOUND_APP" = "1" ] || { echo "sanity: app/server/src/server.js not found in any layer — wrong image?"; exit 2; }

if [ "$fail" = "1" ]; then
  echo "IMAGE PRIVACY SCAN: FAILED"
  exit 1
fi
echo "IMAGE PRIVACY SCAN: CLEAN ($(echo "$LAYERS" | wc -l) blobs scanned)"
