#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
seed_file="$repo_root/distribution/s1-learn/BUILD-SEED.tsv"
release_notes="$repo_root/RELEASE_NOTES.md"

if [[ $# -gt 1 ]]; then
    echo "usage: scripts/package_s1_release.sh [new-output-directory]" >&2
    exit 2
fi

package=$(awk -F '\t' '$1 == "package" { if (found++) exit 3; print $2 } END { if (!found) exit 4 }' "$seed_file")
version=${package#naux@}
if [[ "$package" != "naux@$version" || ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "build seed contains a noncanonical package identity" >&2
    exit 1
fi

target=linux-x86_64-gnu
root_name="naux-learn-$version-$target"
archive_name="$root_name.tar.gz"
checksum_name="$archive_name.sha256"
output=${1:-"$repo_root/target/releases/naux-learn-$version"}
output_parent=$(dirname -- "$output")
output_leaf=$(basename -- "$output")

if [[ -z "$output_leaf" || "$output_leaf" == "." || "$output_leaf" == ".." || "$output" == "/" ]]; then
    echo "refusing unsafe output path: $output" >&2
    exit 2
fi
if [[ -e "$output" || -L "$output" ]]; then
    echo "output path already exists: $output" >&2
    exit 2
fi
for command in cargo gzip readelf rustc sha256sum tar; do
    if ! command -v "$command" > /dev/null 2>&1; then
        echo "required release producer command is missing: $command" >&2
        exit 1
    fi
done
if ! grep -Fx "# NAUX Learn $version" "$release_notes" > /dev/null; then
    echo "release notes version does not match $version" >&2
    exit 1
fi

mkdir -p -- "$output_parent"
output_parent=$(CDPATH= cd -- "$output_parent" && pwd)
output="$output_parent/$output_leaf"
staging=$(mktemp -d "$output_parent/.naux-s1-release.XXXXXXXX")
result="$staging/result"
payload="$staging/payload"

cleanup() {
    rm -rf -- "$staging"
}
trap cleanup EXIT

mkdir -m 0755 -- "$result" "$payload"
"$script_dir/package_s1_learn.sh" "$payload/$root_name"

find "$payload/$root_name" -type d -exec chmod 0755 -- {} +
tar \
    --sort=name \
    --format=ustar \
    --mtime=@0 \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --directory "$payload" \
    --create \
    --file - \
    "$root_name" \
    | gzip --no-name --best > "$result/$archive_name"
chmod 0644 -- "$result/$archive_name"

archive_hash=$(sha256sum -- "$result/$archive_name" | awk '{print $1}')
printf '%s  %s\n' "$archive_hash" "$archive_name" > "$result/$checksum_name"
chmod 0644 -- "$result/$checksum_name"
install -m 0644 -- "$release_notes" "$result/RELEASE_NOTES.md"

"$script_dir/verify_s1_release.sh" \
    "$result/$archive_name" \
    "$result/$checksum_name"

mv -- "$result" "$output"
trap - EXIT
rm -rf -- "$staging"

printf 'release-directory: %s\n' "$output"
printf 'archive: %s\n' "$archive_name"
printf 'archive-sha256: %s\n' "$archive_hash"
