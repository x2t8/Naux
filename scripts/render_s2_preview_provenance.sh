#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

if [[ $# -ne 4 ]]; then
    echo "usage: scripts/render_s2_preview_provenance.sh <release-directory> <source-commit> <source-tree> <bundle-manifest-seal>" >&2
    exit 2
fi

release_dir=$1
source_commit=$2
source_tree=$3
declared_manifest_seal=$4

if [[ ! -d "$release_dir" || -L "$release_dir" ]]; then
    echo "preview provenance input must be a non-link directory" >&2
    exit 1
fi
release_dir=$(CDPATH= cd -- "$release_dir" && pwd)
output="$release_dir/PROVENANCE.tsv"
if [[ -e "$output" || -L "$output" ]]; then
    echo "preview provenance output already exists: $output" >&2
    exit 2
fi
if [[ ! "$source_commit" =~ ^[0-9a-f]{40}$ \
    || ! "$source_tree" =~ ^[0-9a-f]{40}$ \
    || ! "$declared_manifest_seal" =~ ^[0-9a-f]{64}$ ]]; then
    echo "preview provenance source or manifest identity is noncanonical" >&2
    exit 1
fi

for command in awk cat chmod find grep head mktemp mv od rm sha256sum sort stat tail tar tr; do
    if ! command -v "$command" > /dev/null 2>&1; then
        echo "required provenance producer command is missing: $command" >&2
        exit 1
    fi
done

inventory=$(find "$release_dir" -mindepth 1 -maxdepth 1 -printf '%y\t%f\n' | sort)
archive_line=$(printf '%s\n' "$inventory" | awk -F '\t' '$1 == "f" && $2 ~ /^naux-learn-[0-9]+\.[0-9]+\.[0-9]+-linux-x86_64-gnu\.tar\.gz$/ { if (found++) exit 3; print $2 } END { if (!found) exit 4 }')
expected_inventory=$(printf 'f\t%s\nf\tSHA256SUMS\nf\tnauxup.sh\n' "$archive_line" | sort)
if [[ "$inventory" != "$expected_inventory" ]]; then
    echo "preview provenance producer requires the exact three-asset S1 release" >&2
    exit 1
fi

version=${archive_line#naux-learn-}
version=${version%-linux-x86_64-gnu.tar.gz}
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "preview provenance release version is noncanonical" >&2
    exit 1
fi
tag="v$version-learn"
archive="$release_dir/$archive_line"
checksum="$release_dir/SHA256SUMS"
bootstrap="$release_dir/nauxup.sh"

"$script_dir/verify_s1_release.sh" "$archive" "$checksum" > /dev/null

root_name=${archive_line%.tar.gz}
manifest=$(tar --extract --to-stdout --gzip --file "$archive" "$root_name/MANIFEST.tsv")
manifest_seal=$(printf '%s\n' "$manifest" | tail -n 1)
manifest_seal=${manifest_seal#seal$'\t'}
if [[ "$manifest_seal" != "$declared_manifest_seal" ]]; then
    echo "declared bundle manifest seal differs from the release archive" >&2
    exit 1
fi

seed="$repo_root/distribution/s1-learn/BUILD-SEED.tsv"
notes="$repo_root/distribution/s1-learn/RELEASE_NOTES.md"
for input in "$seed" "$notes" "$archive" "$checksum" "$bootstrap"; do
    if [[ ! -f "$input" || -L "$input" ]]; then
        echo "preview provenance input must be a regular non-link file: $input" >&2
        exit 1
    fi
done
if ! grep -Fx "# NAUX Learn $version" "$notes" > /dev/null; then
    echo "preview provenance release notes version differs from the archive" >&2
    exit 1
fi

hash_of() {
    sha256sum -- "$1" | awk '{print $1}'
}

seed_hash=$(hash_of "$seed")
notes_hash=$(hash_of "$notes")
archive_hash=$(hash_of "$archive")
checksum_hash=$(hash_of "$checksum")
bootstrap_hash=$(hash_of "$bootstrap")
archive_bytes=$(stat -c %s -- "$archive")
checksum_bytes=$(stat -c %s -- "$checksum")
bootstrap_bytes=$(stat -c %s -- "$bootstrap")

body=$(mktemp "$release_dir/.naux-provenance-body.XXXXXXXX")
preimage=$(mktemp "$release_dir/.naux-provenance-preimage.XXXXXXXX")
staging=$(mktemp "$release_dir/.naux-provenance-output.XXXXXXXX")
cleanup() {
    rm -f -- "$body" "$preimage" "$staging"
}
trap cleanup EXIT

printf '%s\n' \
    $'NAUX-S2-RELEASE-PROVENANCE\t1' \
    $'product\tnaux-learn' \
    "version"$'\t'"$version" \
    "tag"$'\t'"$tag" \
    $'target\tlinux-x86_64-gnu' \
    "source-commit"$'\t'"$source_commit" \
    "source-tree"$'\t'"$source_tree" \
    "build-seed-sha256"$'\t'"$seed_hash" \
    "release-notes-sha256"$'\t'"$notes_hash" \
    "bundle-manifest-seal"$'\t'"$manifest_seal" \
    "asset"$'\t'"archive"$'\t'"$archive_bytes"$'\t'"$archive_hash"$'\t'"$archive_line" \
    "asset"$'\t'"checksum"$'\t'"$checksum_bytes"$'\t'"$checksum_hash"$'\t'"SHA256SUMS" \
    "asset"$'\t'"bootstrap"$'\t'"$bootstrap_bytes"$'\t'"$bootstrap_hash"$'\t'"nauxup.sh" \
    > "$body"

{
    printf 'NAUX:s2-release-provenance:v1\0'
    cat -- "$body"
} > "$preimage"
seal=$(hash_of "$preimage")
{
    cat -- "$body"
    printf 'seal\t%s\n' "$seal"
} > "$staging"
chmod 0644 -- "$staging"
mv -- "$staging" "$output"
trap - EXIT
rm -f -- "$body" "$preimage"

if ! "$script_dir/verify_s2_preview_provenance.sh" \
    "$release_dir" "$source_commit" "$source_tree" > /dev/null; then
    rm -f -- "$output"
    exit 1
fi

printf 'preview-provenance: %s\n' "$output"
printf 'provenance-seal: %s\n' "$seal"
