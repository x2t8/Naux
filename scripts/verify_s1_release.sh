#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

if [[ $# -ne 2 ]]; then
    echo "usage: scripts/verify_s1_release.sh <archive.tar.gz> <SHA256SUMS>" >&2
    exit 2
fi

archive=$1
checksum=$2
archive_dir=$(CDPATH= cd -- "$(dirname -- "$archive")" && pwd)
archive_base=$(basename -- "$archive")
checksum_dir=$(CDPATH= cd -- "$(dirname -- "$checksum")" && pwd)
checksum_base=$(basename -- "$checksum")

if [[ ! "$archive_base" =~ ^naux-learn-([0-9]+\.[0-9]+\.[0-9]+)-linux-x86_64-gnu\.tar\.gz$ ]]; then
    echo "release archive has a noncanonical name" >&2
    exit 1
fi
version=${BASH_REMATCH[1]}
root_name=${archive_base%.tar.gz}
if [[ "$checksum_base" != "SHA256SUMS" || "$archive_dir" != "$checksum_dir" ]]; then
    echo "release checksum must be the adjacent canonical SHA256SUMS file" >&2
    exit 1
fi
if [[ $(stat -c %s -- "$archive") -gt 20971520 ]]; then
    echo "release archive exceeds the 20 MiB compressed cap" >&2
    exit 1
fi

checksum_line=$(cat -- "$checksum")
declared_hash=${checksum_line%%  *}
expected_checksum_bytes=$((64 + 2 + ${#archive_base} + 1))
if [[ $(stat -c %s -- "$checksum") -ne $expected_checksum_bytes \
    || ! "$declared_hash" =~ ^[0-9a-f]{64}$ \
    || "$checksum_line" != "$declared_hash  $archive_base" ]]; then
    echo "release checksum file is noncanonical" >&2
    exit 1
fi
(
    cd -- "$archive_dir"
    sha256sum --check --strict -- "$checksum_base" > /dev/null
)

temp_root=$(mktemp -d "${TMPDIR:-/tmp}/naux-s1-release-verify.XXXXXXXX")
cleanup() {
    rm -rf -- "$temp_root"
}
trap cleanup EXIT

expected="$temp_root/expected.txt"
actual="$temp_root/actual.txt"
verbose="$temp_root/verbose.txt"
cat > "$expected" <<EOF
$root_name/
$root_name/BUILD-SEED.tsv
$root_name/HOST-DEPENDENCIES.tsv
$root_name/LICENSE
$root_name/MANIFEST.tsv
$root_name/bin/
$root_name/bin/naux
$root_name/bin/nauxup
$root_name/naux-learn-setup
EOF

tar --list --gzip --file "$archive" > "$actual"
cmp -- "$expected" "$actual" > /dev/null
tar --list --verbose --numeric-owner --gzip --file "$archive" > "$verbose"

entry_count=0
total_bytes=0
while IFS= read -r line; do
    type=${line:0:1}
    if [[ "$type" != "-" && "$type" != "d" ]]; then
        echo "release archive contains a non-file, non-directory member" >&2
        exit 1
    fi
    size=$(awk '{print $3}' <<< "$line")
    if [[ ! "$size" =~ ^[0-9]+$ ]]; then
        echo "release archive has a noncanonical size listing" >&2
        exit 1
    fi
    entry_count=$((entry_count + 1))
    total_bytes=$((total_bytes + size))
    if [[ $entry_count -gt 40 || $total_bytes -gt 33554432 ]]; then
        echo "release archive exceeds its entry or expanded-byte cap" >&2
        exit 1
    fi
done < "$verbose"

extract="$temp_root/extract"
mkdir -m 0755 -- "$extract"
tar \
    --extract \
    --gzip \
    --file "$archive" \
    --directory "$extract" \
    --no-same-owner

bundle="$extract/$root_name"
version_output=$("$bundle/bin/naux" --version)
if [[ "$version_output" != "naux $version" ]]; then
    echo "release binary version does not match archive identity" >&2
    exit 1
fi
nauxup_version_output=$("$bundle/bin/nauxup" --version)
if [[ "$nauxup_version_output" != "nauxup $version" ]]; then
    echo "release manager version does not match archive identity" >&2
    exit 1
fi
"$bundle/bin/naux" bundle verify "$bundle" > /dev/null

repacked="$temp_root/repacked.tar.gz"
tar \
    --sort=name \
    --format=ustar \
    --mtime=@0 \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --directory "$extract" \
    --create \
    --file - \
    "$root_name" \
    | gzip --no-name --best > "$repacked"
if ! cmp -- "$archive" "$repacked" > /dev/null; then
    echo "release archive is not the canonical deterministic encoding" >&2
    exit 1
fi

printf 'release-archive: verified\n'
printf 'version: %s\n' "$version"
printf 'entries: %s\n' "$entry_count"
printf 'expanded-bytes: %s\n' "$total_bytes"
