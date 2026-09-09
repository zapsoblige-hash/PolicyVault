#!/usr/bin/env bash
# Rebuild the pinned native/debug and WASM/release tools with neutral source
# paths. Output MUST be fresh; existing toolchains and vendor evidence survive.
# Run their applicable behavioral gates before promoting the new byte pins.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:?usage: build-private-safe-vendor.sh <fresh absolute output directory>}"
SS="${POLICYVAULT_SILVERSCRIPT_SOURCE:-$HOME/silverscript}"
RK="${POLICYVAULT_RUSTY_KASPA_SOURCE:-$HOME/rusty-kaspa}"
case "$OUT" in /*) ;; *) echo 'output must be absolute' >&2; exit 2;; esac
[ ! -e "$OUT" ] || { echo 'refusing existing output; inspect interrupted evidence before resuming' >&2; exit 2; }
[ "$(git -C "$SS" rev-parse HEAD)" = d25bd3427a093c17327ca3d6b9e1aa5f7688c863 ]
[ "$(git -C "$RK" rev-parse HEAD)" = cfafeb4c093fa37a303f1b9f19c58f986b870ce3 ]
git -C "$SS" diff --exit-code --quiet HEAD
git -C "$RK" diff --exit-code --quiet HEAD
mkdir -p "$OUT/bin"
# rustc uses the LAST matching prefix. Broad home remap precedes specific
# repo/toolchain remaps, including the lexical sibling path used by Cargo.
REMAP="--remap-path-prefix=$HOME=/build --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup --remap-path-prefix=$(dirname "$ROOT")=/src/workspaces --remap-path-prefix=$SS=/src/silverscript --remap-path-prefix=$RK=/src/rusty-kaspa --remap-path-prefix=$ROOT=/src/policyvault"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export RUSTFLAGS="$REMAP"
export CARGO_TARGET_DIR="$OUT/native-target"
cargo build --locked --offline --manifest-path "$SS/Cargo.toml" --bin silverc
cp "$CARGO_TARGET_DIR/debug/silverc" "$OUT/bin/silverc"
cargo build --locked --offline --manifest-path "$ROOT/tests/vm/Cargo.toml" --bins
for b in pv_call_encoder pv_vm_preflight pv_tx_probe; do cp "$CARGO_TARGET_DIR/debug/$b" "$OUT/bin/$b"; done
# Match upstream wasm/build-node, which otherwise overwrites RUSTFLAGS.
export RUSTFLAGS="-Ctarget-cpu=mvp $REMAP"
export CARGO_TARGET_DIR="$OUT/wasm-target"
(cd "$RK/wasm" && wasm-pack build --weak-refs --target nodejs --out-name kaspa --out-dir "$OUT/kaspa" --features wasm32-sdk --locked --offline)
# C/assembly dependency debug directories are not covered by rustc remaps.
# Remove non-runtime debug sections only AFTER remapping runtime strings;
# stripping the original unremapped executables alone would still leak paths.
for b in "$OUT"/bin/*; do objcopy --strip-debug "$b"; done
(cd "$OUT" && find bin kaspa -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt)
echo 'BUILD COMPLETE — new bytes require privacy and behavioral verification'
