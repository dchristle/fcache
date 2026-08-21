#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -lt 1 || "$#" -gt 2 ]]; then
    echo "usage: $0 <fcache-binary> [gfortran-command]" >&2
    exit 2
fi

binary_dir="$(cd -- "$(dirname -- "$1")" && pwd)"
binary="$binary_dir/$(basename -- "$1")"
compiler="${2:-gfortran}"

if [[ ! -x "$binary" ]]; then
    echo "fcache binary is missing or not executable: $binary" >&2
    exit 1
fi
if ! command -v "$compiler" >/dev/null 2>&1; then
    echo "Fortran compiler is not available: $compiler" >&2
    exit 1
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/fcache-release-smoke.XXXXXX")"
trap 'rm -r "$work_dir"' EXIT

cache_dir="$work_dir/cache"
build_dir="$work_dir/build"
snapshot_dir="$work_dir/cold"
mkdir -p "$build_dir/modules" "$snapshot_dir"

cat > "$build_dir/release_smoke.F90" <<'EOF'
module release_smoke_mod
  implicit none
contains
  integer function release_smoke_value()
    release_smoke_value = 42
  end function release_smoke_value
end module release_smoke_mod
EOF

"$binary" --version

compile() {
    FCACHE_DIR="$cache_dir" "$binary" "$compiler" \
        -cpp \
        -c release_smoke.F90 \
        -J modules \
        -MD \
        -MF release_smoke.d \
        -o release_smoke.o
}

(
    cd "$build_dir"
    compile
    cp release_smoke.o release_smoke.d modules/release_smoke_mod.mod "$snapshot_dir/"
    rm release_smoke.o release_smoke.d modules/release_smoke_mod.mod
    compile
    cmp release_smoke.o "$snapshot_dir/release_smoke.o"
    cmp release_smoke.d "$snapshot_dir/release_smoke.d"
    cmp modules/release_smoke_mod.mod "$snapshot_dir/release_smoke_mod.mod"
)

FCACHE_DIR="$cache_dir" "$binary" --show-stats --json | python3 -c '
import json
import sys

stats = json.load(sys.stdin)
if stats["lookup_results"]["hits"] < 1:
    raise SystemExit("packaged binary smoke test did not produce a cache hit")
if stats["observed_outcomes"]["cache_hit_success"] < 1:
    raise SystemExit("packaged binary smoke test did not restore a cached result")
'

echo "packaged binary smoke test passed"
