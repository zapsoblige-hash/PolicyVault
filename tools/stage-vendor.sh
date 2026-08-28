#!/usr/bin/env bash
# Stage the runtime artifacts the PolicyVault container needs but which
# live OUTSIDE the repository tree (authoritative external toolchains) or
# in gitignored build output, into deploy/vendor/ (gitignored), with a
# SHA256 manifest recorded for the Phase E evidence.
#
# The staged binaries are the EXACT binaries the release gate ran on this
# machine — the container runs the verified bytes, it does not rebuild
# them. (A from-source containerized toolchain build is a possible later
# improvement; it would need the pinned silverscript + rusty-kaspa source
# trees inside the build context and a full Rust toolchain stage.)
#
#   deploy/vendor/kaspa/                  <- ~/rusty-kaspa/wasm/nodejs/kaspa (pinned kaspa-wasm)
#   deploy/vendor/bin/silverc            <- ~/silverscript/target/debug/silverc
#   deploy/vendor/bin/pv_call_encoder    <- tests/vm/target/debug/ (production covenant-call encoder)
#   deploy/vendor/bin/pv_vm_preflight    <- tests/vm/target/debug/ (real-VM preflight)
#   deploy/vendor/bin/pv_tx_probe        <- tests/vm/target/debug/ (frozen-tx/approval verification)
#   deploy/vendor/dist/node-v20.20.2-linux-x64.tar.xz  (pre-fetched, SHASUMS256-verified)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$REPO_ROOT/deploy/vendor"

mkdir -p "$VENDOR/bin"

echo "staging kaspa-wasm module..."
rm -rf "$VENDOR/kaspa"
cp -r "$HOME/rusty-kaspa/wasm/nodejs/kaspa" "$VENDOR/kaspa"

echo "staging silverc + pv binaries..."
cp "$HOME/silverscript/target/debug/silverc" "$VENDOR/bin/silverc"
for b in pv_call_encoder pv_vm_preflight pv_tx_probe; do
  cp "$REPO_ROOT/tests/vm/target/debug/$b" "$VENDOR/bin/$b"
done
chmod 755 "$VENDOR/bin/"*

echo "writing SHA256 manifest..."
(
  cd "$VENDOR"
  find bin kaspa dist -type f 2>/dev/null | sort | xargs sha256sum > SHA256SUMS.txt
)

echo "staged. manifest:"
grep -E "bin/|node-v" "$VENDOR/SHA256SUMS.txt"
