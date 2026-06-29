#!/usr/bin/env bash
#
# configure_paths.sh — make the ORANalyst Go fuzzer build from THIS clone.
#
# ORANalyst's go-fuzz build embeds ABSOLUTE cgo include/lib paths and an
# absolute `replace` directive in several Go files. They were captured on the
# original build host, so after cloning this repo somewhere else you must point
# them at your checkout. This script rewrites every stale absolute prefix to the
# oran-input-gen directory inside this clone.
#
# Run once after cloning, before `make fuzzer`:
#     ./configure_paths.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN_DIR="$REPO_ROOT/ORANalyst/O-RAN-SC/oran-input-gen"

if [ ! -d "$GEN_DIR" ]; then
  echo "error: $GEN_DIR not found" >&2
  exit 1
fi

# Any previous absolute path that ends in .../oran-input-gen is rewritten to
# this clone's oran-input-gen. Matches both the original author's path and a
# prior local build's path.
echo "[configure] pointing cgo/replace paths at: $GEN_DIR"

# Files known to carry absolute paths (cgo CFLAGS/LDFLAGS + go.mod replace).
mapfile -t FILES < <(grep -rlE '/[^ "]*oran-input-gen(/kpm|/go-fuzz)?' \
  --include='*.go' --include='go.mod' "$GEN_DIR" 2>/dev/null || true)

for f in "${FILES[@]}"; do
  # Rewrite the directory prefix up to and including 'oran-input-gen'.
  sed -i -E "s#/[^ \"]*/oran-input-gen#$GEN_DIR#g" "$f"
  echo "  patched: ${f#$REPO_ROOT/}"
done

echo "[configure] done. Now build with:"
echo "    export PATH=\$HOME/.local/go/bin:\$PATH GOTOOLCHAIN=local"
echo "    cd \"$GEN_DIR\" && make fuzzer"
