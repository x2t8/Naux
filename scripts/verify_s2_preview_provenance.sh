#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

if [[ $# -ne 3 ]]; then
    echo "usage: scripts/verify_s2_preview_provenance.sh <release-directory> <expected-source-commit> <expected-source-tree>" >&2
    exit 2
fi

release_dir=$1
expected_commit=$2
expected_tree=$3
if [[ ! -d "$release_dir" || -L "$release_dir" ]]; then
    echo "preview release must be a non-link directory" >&2
    exit 1
fi
release_dir=$(CDPATH= cd -- "$release_dir" && pwd)
if [[ ! "$expected_commit" =~ ^[0-9a-f]{40}$ || ! "$expected_tree" =~ ^[0-9a-f]{40}$ ]]; then
    echo "expected source identity is noncanonical" >&2
    exit 1
fi

for command in awk cat find grep head mktemp od rm sha256sum sort stat tail tar tr; do
    if ! command -v "$command" > /dev/null 2>&1; then
        echo "required provenance verifier command is missing: $command" >&2
        exit 1
    fi
done

provenance="$release_dir/PROVENANCE.tsv"
if [[ ! -f "$provenance" || -L "$provenance" ]]; then
    echo "preview provenance must be a regular non-link file" >&2
    exit 1
fi
provenance_bytes=$(stat -c %s -- "$provenance")
provenance_mode=$(stat -c %a -- "$provenance")
if [[ $provenance_bytes -le 0 || $provenance_bytes -gt 4096 \
    || "$provenance_mode" != "644" ]]; then
    echo "preview provenance size or mode is noncanonical" >&2
    exit 1
fi
last_byte=$(tail -c 1 -- "$provenance" | od -An -tx1 | tr -d ' \n')
if [[ "$last_byte" != "0a" ]]; then
    echo "preview provenance must end in exactly one LF-terminated row" >&2
    exit 1
fi
if od -An -tx1 -v -- "$provenance" | tr ' ' '\n' | grep -Eq '^(00|0d)$'; then
    echo "preview provenance contains NUL or carriage return bytes" >&2
    exit 1
fi

readarray -t lines < "$provenance"
if [[ ${#lines[@]} -ne 14 || "${lines[0]}" != $'NAUX-S2-RELEASE-PROVENANCE\t1' ]]; then
    echo "preview provenance magic, version, or row count mismatch" >&2
    exit 1
fi

pair_value() {
    local line=$1
    local expected_key=$2
    local value
    if [[ "$line" != "$expected_key"$'\t'* ]]; then
        echo "preview provenance expected field: $expected_key" >&2
        return 1
    fi
    value=${line#*$'\t'}
    if [[ -z "$value" || "$value" == *$'\t'* ]]; then
        echo "preview provenance field is empty or has extra columns: $expected_key" >&2
        return 1
    fi
    printf '%s' "$value"
}

product=$(pair_value "${lines[1]}" product)
version=$(pair_value "${lines[2]}" version)
tag=$(pair_value "${lines[3]}" tag)
target=$(pair_value "${lines[4]}" target)
source_commit=$(pair_value "${lines[5]}" source-commit)
source_tree=$(pair_value "${lines[6]}" source-tree)
seed_hash=$(pair_value "${lines[7]}" build-seed-sha256)
notes_hash=$(pair_value "${lines[8]}" release-notes-sha256)
manifest_seal=$(pair_value "${lines[9]}" bundle-manifest-seal)
declared_seal=$(pair_value "${lines[13]}" seal)

if [[ "$product" != "naux-learn" \
    || ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ \
    || "$tag" != "v$version-learn" \
    || "$target" != "linux-x86_64-gnu" \
    || "$source_commit" != "$expected_commit" \
    || "$source_tree" != "$expected_tree" \
    || ! "$seed_hash" =~ ^[0-9a-f]{64}$ \
    || ! "$notes_hash" =~ ^[0-9a-f]{64}$ \
    || ! "$manifest_seal" =~ ^[0-9a-f]{64}$ \
    || ! "$declared_seal" =~ ^[0-9a-f]{64}$ ]]; then
    echo "preview provenance identity or source binding mismatch" >&2
    exit 1
fi

parse_asset() {
    local line=$1
    local expected_kind=$2
    local expected_name=$3
    local destination_prefix=$4
    local fields
    IFS=$'\t' read -r -a fields <<< "$line"
    if [[ ${#fields[@]} -ne 5 \
        || "${fields[0]}" != "asset" \
        || "${fields[1]}" != "$expected_kind" \
        || ! "${fields[2]}" =~ ^[1-9][0-9]*$ \
        || ! "${fields[3]}" =~ ^[0-9a-f]{64}$ \
        || "${fields[4]}" != "$expected_name" ]]; then
        echo "preview provenance asset row is noncanonical: $expected_kind" >&2
        return 1
    fi
    printf -v "${destination_prefix}_bytes" '%s' "${fields[2]}"
    printf -v "${destination_prefix}_hash" '%s' "${fields[3]}"
}

archive_name="naux-learn-$version-linux-x86_64-gnu.tar.gz"
parse_asset "${lines[10]}" archive "$archive_name" archive
parse_asset "${lines[11]}" checksum SHA256SUMS checksum
parse_asset "${lines[12]}" bootstrap nauxup.sh bootstrap
if [[ $checksum_bytes -gt 65536 || $bootstrap_bytes -gt 65536 ]]; then
    echo "preview checksum or bootstrap exceeds its public asset cap" >&2
    exit 1
fi

inventory=$(find "$release_dir" -mindepth 1 -maxdepth 1 -printf '%y\t%f\n' | sort)
expected_inventory=$(printf 'f\t%s\nf\tPROVENANCE.tsv\nf\tSHA256SUMS\nf\tnauxup.sh\n' "$archive_name" | sort)
if [[ "$inventory" != "$expected_inventory" ]]; then
    echo "preview release inventory is not the exact four-file set" >&2
    exit 1
fi

archive="$release_dir/$archive_name"
checksum="$release_dir/SHA256SUMS"
bootstrap="$release_dir/nauxup.sh"
for asset in "$archive" "$checksum" "$bootstrap"; do
    if [[ ! -f "$asset" || -L "$asset" ]]; then
        echo "preview asset must be a regular non-link file: $asset" >&2
        exit 1
    fi
done
if [[ $(stat -c %a -- "$archive") != "644" \
    || $(stat -c %a -- "$checksum") != "644" \
    || $(stat -c %a -- "$bootstrap") != "755" ]]; then
    echo "preview asset mode differs from the canonical transport mode" >&2
    exit 1
fi

hash_of() {
    sha256sum -- "$1" | awk '{print $1}'
}

if [[ $(stat -c %s -- "$archive") != "$archive_bytes" \
    || $(hash_of "$archive") != "$archive_hash" \
    || $(stat -c %s -- "$checksum") != "$checksum_bytes" \
    || $(hash_of "$checksum") != "$checksum_hash" \
    || $(stat -c %s -- "$bootstrap") != "$bootstrap_bytes" \
    || $(hash_of "$bootstrap") != "$bootstrap_hash" ]]; then
    echo "preview asset differs from its provenance row" >&2
    exit 1
fi

seed="$repo_root/distribution/s1-learn/BUILD-SEED.tsv"
notes="$repo_root/distribution/s1-learn/RELEASE_NOTES.md"
if [[ $(hash_of "$seed") != "$seed_hash" || $(hash_of "$notes") != "$notes_hash" ]]; then
    echo "preview source metadata differs from the provenance binding" >&2
    exit 1
fi

"$script_dir/verify_s1_release.sh" "$archive" "$checksum" > /dev/null
root_name=${archive_name%.tar.gz}
manifest=$(tar --extract --to-stdout --gzip --file "$archive" "$root_name/MANIFEST.tsv")
actual_manifest_seal=$(printf '%s\n' "$manifest" | tail -n 1)
actual_manifest_seal=${actual_manifest_seal#seal$'\t'}
if [[ "$actual_manifest_seal" != "$manifest_seal" ]]; then
    echo "preview bundle manifest differs from the provenance binding" >&2
    exit 1
fi

temp_root=$(mktemp -d "${TMPDIR:-/tmp}/naux-s2-provenance-verify.XXXXXXXX")
cleanup() {
    rm -rf -- "$temp_root"
}
trap cleanup EXIT
body="$temp_root/body"
preimage="$temp_root/preimage"
head -n 13 -- "$provenance" > "$body"
{
    printf 'NAUX:s2-release-provenance:v1\0'
    cat -- "$body"
} > "$preimage"
actual_seal=$(hash_of "$preimage")
if [[ "$actual_seal" != "$declared_seal" ]]; then
    echo "preview provenance seal mismatch" >&2
    exit 1
fi

printf 'preview-provenance: verified\n'
printf 'version: %s\n' "$version"
printf 'tag: %s\n' "$tag"
printf 'source-commit: %s\n' "$source_commit"
printf 'source-tree: %s\n' "$source_tree"
printf 'archive-sha256: %s\n' "$archive_hash"
printf 'provenance-seal: %s\n' "$declared_seal"
