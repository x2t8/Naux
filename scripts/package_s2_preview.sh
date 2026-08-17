#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
seed="$repo_root/distribution/s1-learn/BUILD-SEED.tsv"

if [[ $# -gt 1 ]]; then
    echo "usage: scripts/package_s2_preview.sh [new-output-directory]" >&2
    exit 2
fi
for command in awk git mkdir mktemp mv rm tar; do
    if ! command -v "$command" > /dev/null 2>&1; then
        echo "required preview producer command is missing: $command" >&2
        exit 1
    fi
done

package=$(awk -F '\t' '$1 == "package" { if (found++) exit 3; print $2 } END { if (!found) exit 4 }' "$seed")
version=${package#naux@}
tag="v$version-learn"
if [[ "$package" != "naux@$version" || ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "preview build seed contains a noncanonical package identity" >&2
    exit 1
fi

if [[ -n $(git -C "$repo_root" status --porcelain=v1 --untracked-files=all) ]]; then
    echo "preview publication requires a clean source worktree" >&2
    exit 1
fi
head_commit=$(git -C "$repo_root" rev-parse --verify HEAD)
head_tree=$(git -C "$repo_root" rev-parse --verify 'HEAD^{tree}')
tag_type=$(git -C "$repo_root" cat-file -t "$tag" 2>/dev/null || true)
tag_commit=$(git -C "$repo_root" rev-parse --verify "$tag^{commit}" 2>/dev/null || true)
if [[ "$tag_type" != "tag" || "$tag_commit" != "$head_commit" ]]; then
    echo "preview publication requires annotated tag $tag at clean HEAD" >&2
    exit 1
fi

output=${1:-"$repo_root/target/previews/naux-learn-$version"}
output_parent=$(dirname -- "$output")
output_leaf=$(basename -- "$output")
if [[ -z "$output_leaf" || "$output_leaf" == "." || "$output_leaf" == ".." || "$output" == "/" ]]; then
    echo "refusing unsafe preview output path: $output" >&2
    exit 2
fi
if [[ -e "$output" || -L "$output" ]]; then
    echo "preview output path already exists: $output" >&2
    exit 2
fi

mkdir -p -- "$output_parent"
output_parent=$(CDPATH= cd -- "$output_parent" && pwd)
output="$output_parent/$output_leaf"
staging=$(mktemp -d "$output_parent/.naux-s2-preview.XXXXXXXX")
release="$staging/release"
cleanup() {
    rm -rf -- "$staging"
}
trap cleanup EXIT

"$script_dir/package_s1_release.sh" "$release"
archive="$release/naux-learn-$version-linux-x86_64-gnu.tar.gz"
root_name="naux-learn-$version-linux-x86_64-gnu"
manifest=$(tar --extract --to-stdout --gzip --file "$archive" "$root_name/MANIFEST.tsv")
manifest_seal=$(printf '%s\n' "$manifest" | tail -n 1)
manifest_seal=${manifest_seal#seal$'\t'}
"$script_dir/render_s2_preview_provenance.sh" \
    "$release" "$head_commit" "$head_tree" "$manifest_seal"
"$script_dir/verify_s2_preview_provenance.sh" \
    "$release" "$head_commit" "$head_tree"

mv -- "$release" "$output"
trap - EXIT
rm -rf -- "$staging"

printf 'preview-directory: %s\n' "$output"
printf 'source-commit: %s\n' "$head_commit"
printf 'source-tree: %s\n' "$head_tree"
