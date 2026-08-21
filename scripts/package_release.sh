#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 2 ]]; then
    echo "usage: $0 <version> <target>" >&2
    exit 2
fi

version="$1"
target="$2"
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
dist_dir="${FCACHE_DIST_DIR:-$project_root/dist}"
package="fcache-$version-$target"
package_dir="$dist_dir/$package"
archive="$dist_dir/$package.tar.gz"
binary="$project_root/target/$target/release/fcache"

if [[ ! -x "$binary" ]]; then
    echo "release binary is missing or not executable: $binary" >&2
    exit 1
fi

if [[ -e "$package_dir" || -e "$archive" || -e "$archive.sha256" ]]; then
    echo "release package output already exists for $package" >&2
    exit 1
fi

install -d "$package_dir/scripts"
install -m 755 "$binary" "$package_dir/fcache"
install -m 755 \
    "$project_root/scripts/benchmark_acceptance.py" \
    "$package_dir/scripts/benchmark_acceptance.py"
cp \
    "$project_root/README.md" \
    "$project_root/CHANGELOG.md" \
    "$project_root/LICENSE-APACHE" \
    "$project_root/LICENSE-MIT" \
    "$package_dir/"

COPYFILE_DISABLE=1 tar -C "$dist_dir" -czf "$archive" "$package"

(
    cd "$dist_dir"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$package.tar.gz" > "$package.tar.gz.sha256"
    else
        shasum -a 256 "$package.tar.gz" > "$package.tar.gz.sha256"
    fi
)
