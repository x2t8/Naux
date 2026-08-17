#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

if [[ $# -ne 4 ]]; then
    echo "usage: scripts/render_s1_bootstrap.sh <linux|windows> <archive> <checksum> <new-output>" >&2
    exit 2
fi

platform=$1
archive=$2
checksum=$3
output=$4

case "$platform" in
    linux)
        template="$repo_root/distribution/s1-learn/bootstrap/nauxup.sh.in"
        expected_suffix='-linux-x86_64-gnu.tar.gz'
        ;;
    windows)
        template="$repo_root/distribution/s1-learn/bootstrap/nauxup.ps1.in"
        expected_suffix='-windows-x86_64-gnu.zip'
        ;;
    *)
        echo "unsupported bootstrap platform: $platform" >&2
        exit 2
        ;;
esac

for input in "$archive" "$checksum" "$template"; do
    if [[ ! -f "$input" || -L "$input" ]]; then
        echo "bootstrap input must be a regular non-link file: $input" >&2
        exit 1
    fi
done
if [[ -e "$output" || -L "$output" ]]; then
    echo "bootstrap output already exists: $output" >&2
    exit 2
fi

archive_name=$(basename -- "$archive")
if [[ "$archive_name" != naux-learn-*"$expected_suffix" ]]; then
    echo "bootstrap archive name is noncanonical for $platform" >&2
    exit 1
fi
version=${archive_name#naux-learn-}
version=${version%"$expected_suffix"}
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "bootstrap archive version is noncanonical" >&2
    exit 1
fi
tag="v$version-learn"

archive_hash=$(sha256sum -- "$archive" | awk '{print $1}')
expected_line="$archive_hash  $archive_name"
expected_bytes=$((${#expected_line} + 1))
actual_checksum_bytes=$(wc -c < "$checksum")
if [[ "$actual_checksum_bytes" -ne "$expected_bytes" ]] \
    || ! grep -Fx -- "$expected_line" "$checksum" > /dev/null; then
    echo "bootstrap checksum file is noncanonical or does not bind the archive" >&2
    exit 1
fi
archive_bytes=$(wc -c < "$archive")
if [[ "$archive_bytes" -le 0 || "$archive_bytes" -gt 20971520 ]]; then
    echo "bootstrap archive size is outside the admitted release envelope" >&2
    exit 1
fi

output_parent=$(dirname -- "$output")
mkdir -p -- "$output_parent"
staging=$(mktemp "$output_parent/.naux-bootstrap.XXXXXXXX")
cleanup() {
    rm -f -- "$staging"
}
trap cleanup EXIT

sed \
    -e "s/@@VERSION@@/$version/g" \
    -e "s/@@TAG@@/$tag/g" \
    -e "s/@@ARCHIVE@@/$archive_name/g" \
    -e "s/@@ARCHIVE_SHA256@@/$archive_hash/g" \
    -e "s/@@ARCHIVE_BYTES@@/$archive_bytes/g" \
    "$template" > "$staging"
if grep -F '@@' "$staging" > /dev/null; then
    echo "bootstrap template contains an unresolved token" >&2
    exit 1
fi

if [[ "$platform" == linux ]]; then
    sh -n "$staging"
    # GitHub Release assets are downloaded as ordinary files. Keep the local
    # producer byte-for-byte and mode-for-mode aligned with that transport;
    # callers execute the reviewed bootstrap explicitly with `sh`.
    chmod 0644 -- "$staging"
else
    chmod 0644 -- "$staging"
fi
mv -- "$staging" "$output"
trap - EXIT
