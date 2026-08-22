#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
lock="$repo_root/distribution/s2-preview/RELEASE-PROVENANCE.tsv"
temp_root=$(mktemp -d "${TMPDIR:-/tmp}/naux-s2-public-release.XXXXXXXX")

cleanup() {
    rm -rf -- "$temp_root"
}
trap cleanup EXIT

for command in awk cmp curl grep head od sha256sum stat tail tar tr; do
    if ! command -v "$command" > /dev/null 2>&1; then
        echo "required public-release replay command is missing: $command" >&2
        exit 1
    fi
done
if [[ ! -f "$lock" || -L "$lock" || $(stat -c %a -- "$lock") != 644 ]]; then
    echo "public-release provenance lock must be a mode-0644 regular file" >&2
    exit 1
fi
if [[ $(tail -c 1 -- "$lock" | od -An -tx1 | tr -d ' \n') != 0a ]]; then
    echo "public-release provenance lock must end in LF" >&2
    exit 1
fi

readarray -t lock_lines < "$lock"
if [[ ${#lock_lines[@]} -ne 14 \
    || "${lock_lines[0]}" != $'NAUX-S2-RELEASE-PROVENANCE\t1' ]]; then
    echo "public-release provenance lock schema drift" >&2
    exit 1
fi
declared_seal=${lock_lines[13]#seal$'\t'}
actual_seal=$(
    {
        printf 'NAUX:s2-release-provenance:v1\0'
        head -n 13 -- "$lock"
    } | sha256sum | awk '{print $1}'
)
if [[ "${lock_lines[13]}" != seal$'\t'"$declared_seal" \
    || ! "$declared_seal" =~ ^[0-9a-f]{64}$ \
    || "$actual_seal" != "$declared_seal" ]]; then
    echo "public-release provenance lock seal mismatch" >&2
    exit 1
fi

field() {
    local key=$1
    awk -F '\t' -v key="$key" '
        $1 == key { if (found++) exit 3; print $2 }
        END { if (!found) exit 4 }
    ' "$lock"
}

version=$(field version)
tag=$(field tag)
source_commit=$(field source-commit)
source_tree=$(field source-tree)
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ \
    || "$tag" != "v$version-learn" \
    || ! "$source_commit" =~ ^[0-9a-f]{40}$ \
    || ! "$source_tree" =~ ^[0-9a-f]{40}$ ]]; then
    echo "public-release provenance lock identity is noncanonical" >&2
    exit 1
fi

archive_name="naux-learn-$version-linux-x86_64-gnu.tar.gz"
base_url="https://github.com/x2t8/Naux/releases/download/$tag"
for asset in "$archive_name" SHA256SUMS nauxup.sh PROVENANCE.tsv; do
    curl \
        --proto '=https' \
        --tlsv1.2 \
        --fail \
        --silent \
        --show-error \
        --location \
        --retry 3 \
        --output "$temp_root/$asset" \
        "$base_url/$asset"
    chmod 0644 -- "$temp_root/$asset"
done

if ! cmp -- "$lock" "$temp_root/PROVENANCE.tsv"; then
    echo "published provenance differs from the repository lock" >&2
    exit 1
fi
"$script_dir/verify_s2_preview_provenance.sh" \
    "$temp_root" "$source_commit" "$source_tree" > /dev/null

bundle_contract="$repo_root/docs/s1_learn_binary_bundle.md"
contract_flat=$(tr '\n' ' ' < "$bundle_contract" | tr -d ',')
archive="$temp_root/$archive_name"
archive_bytes=$(stat -c %s -- "$archive")
archive_hash=$(sha256sum -- "$archive" | awk '{print $1}')
root_name=${archive_name%.tar.gz}
manifest=$(tar --extract --to-stdout --gzip --file "$archive" "$root_name/MANIFEST.tsv")
manifest_seal=$(printf '%s\n' "$manifest" | tail -n 1)
manifest_seal=${manifest_seal#seal$'\t'}
expanded_bytes=$(
    tar --list --verbose --numeric-owner --gzip --file "$archive" \
        | awk '{ total += $3 } END { print total }'
)
for expected_contract_fragment in \
    "package \`naux@$version\`" \
    "bundle<TAB>$version" \
    "$expanded_bytes admitted bytes" \
    "manifest seal \`$manifest_seal\`" \
    "$archive_bytes bytes" \
    "SHA-256 \`$archive_hash\`"; do
    if [[ "$contract_flat" != *"$expected_contract_fragment"* ]]; then
        echo "binary-bundle contract differs from published release evidence: $expected_contract_fragment" >&2
        exit 1
    fi
done

printf 'S2 public release provenance lock: PASS\n'
printf 'S2 public release download and independent replay: PASS\n'
printf 'S2 public release documentation synchronization: PASS\n'
