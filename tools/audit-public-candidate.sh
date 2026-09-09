#!/usr/bin/env bash
# Fail-closed pattern gate for an exported public tree (no .git/private data).
# Exact byte classifications must be independently reviewed when source changes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TREE="${1:?usage: audit-public-candidate.sh <exported public tree> [scanner options]}"; shift
exec python3 "$ROOT/tools/artifact-privacy-scan.py" --tree "$TREE" --classifications "$ROOT/tools/public-privacy-classifications.json" "$@"
