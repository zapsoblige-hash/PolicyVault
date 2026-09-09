#!/usr/bin/env bash
# Shared helpers for the PolicyVault deployment pipeline (Track 8).
#
# Design rules these helpers exist to enforce:
#   - every artifact is CONTENT-ADDRESSED and verified by sha256 on both
#     sides of the transfer (never trusted because it arrived);
#   - every file this pipeline writes is written to a temp path and
#     ATOMICALLY renamed, so an interrupted step never leaves a half
#     artifact that a later step could mistake for a complete one;
#   - unknown/ambiguous state FAILS CLOSED (never a default, never a guess).
#
# Sourced, never executed directly. No new dependencies: coreutils, tar,
# git, docker, and OpenSSH's ssh-keygen -Y only.

pv_log()  { printf '[pv-pipeline] %s\n' "$*" >&2; }
pv_die()  { printf '[pv-pipeline] FATAL: %s\n' "$*" >&2; exit 1; }
pv_need() { command -v "$1" >/dev/null 2>&1 || pv_die "required command not found: $1"; }

pv_sha256() { sha256sum "$1" | awk '{print $1}'; }

# Atomic write: pv_atomic_install <tmpfile> <finalpath>. Preserves the
# destination's existing mode when it already exists (production env
# files are 600 root:root — a deploy must never widen them).
pv_atomic_install() {
  local tmp="$1" final="$2" mode=""
  [ -f "$tmp" ] || pv_die "atomic install: temp file missing: $tmp"
  if [ -e "$final" ]; then mode="$(stat -c '%a' "$final")"; fi
  if [ -n "$mode" ]; then chmod "$mode" "$tmp"; fi
  mv -f "$tmp" "$final"
}

# Deterministic tar of a directory's contents: identical bytes for
# identical content regardless of build time, uid/gid, or readdir order.
# out="-" streams to stdout (used to pipe an assembled image straight into
# `docker load` without ever materialising a second full-size archive).
pv_tar_deterministic() {
  local dir="$1" out="$2" epoch="${3:-0}"
  # NOTE: every option must precede --files-from (GNU tar treats the names
  # it reads as non-option arguments and ignores options that follow).
  ( cd "$dir" && find . -mindepth 1 -printf '%P\0' | LC_ALL=C sort -z \
    | tar --create --file - \
          --sort=name --mtime="@${epoch}" \
          --owner=0 --group=0 --numeric-owner \
          --format=pax --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
          --no-recursion --null --files-from=- ) > "${out/#-/\/dev\/stdout}"
}

# OCI archive helpers ------------------------------------------------------
# An OCI image archive (docker buildx --output type=oci) is a tar of:
#   oci-layout, index.json, blobs/sha256/<sha256-of-the-blob>
# Every blob's FILENAME is its own sha256 — the whole format is
# content-addressed, which is exactly what makes delta transfer safe.

# Print "<blobname> <bytes>" for each blob in an OCI archive.
pv_oci_blobs() {
  tar -tvf "$1" | awk '$1 !~ /^d/ && $6 ~ /^blobs\/sha256\/./ { n=$6; sub(/^blobs\/sha256\//,"",n); print n, $3 }' | LC_ALL=C sort
}

# The image manifest digest an OCI archive resolves to (= the image ID
# `docker load` produces). Fails closed on multi-manifest archives, which
# this pipeline never produces (--provenance=false --sbom=false).
pv_oci_image_digest() {
  local tarball="$1" tmp digests n
  tmp="$(mktemp -d)"
  if ! tar -xf "$tarball" -C "$tmp" index.json 2>/dev/null; then
    rm -rf "$tmp"; pv_die "not an OCI archive (no index.json): $tarball"
  fi
  digests="$(tr '{},' '\n' < "$tmp/index.json" \
    | grep -o '"digest":"sha256:[0-9a-f]\{64\}"' \
    | sed 's/.*"sha256:/sha256:/;s/"$//')"
  rm -rf "$tmp"
  n="$(printf '%s' "$digests" | grep -c . || true)"
  [ "$n" = "1" ] || pv_die "OCI archive index lists $n manifests — this pipeline requires exactly one (build with --provenance=false --sbom=false)"
  printf '%s\n' "$digests"
}

pv_require_digest_format() {
  case "$1" in
    sha256:[0-9a-f][0-9a-f]*) [ "${#1}" = 71 ] || pv_die "malformed digest: $1" ;;
    *) pv_die "malformed digest (expected sha256:<64 hex>): $1" ;;
  esac
}
