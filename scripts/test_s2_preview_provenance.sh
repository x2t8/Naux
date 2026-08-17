#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
temp_root=$(mktemp -d "${TMPDIR:-/tmp}/naux-s2-preview-test.XXXXXXXX")
source_commit=1111111111111111111111111111111111111111
source_tree=2222222222222222222222222222222222222222

cleanup() {
    rm -rf -- "$temp_root"
}
trap cleanup EXIT

release_a="$temp_root/release-a"
release_b="$temp_root/release-b"
"$script_dir/package_s1_release.sh" "$release_a" > /dev/null
"$script_dir/package_s1_release.sh" "$release_b" > /dev/null

package=$(awk -F '\t' '$1 == "package" { print $2; exit }' "$repo_root/distribution/s1-learn/BUILD-SEED.tsv")
version=${package#naux@}
archive_name="naux-learn-$version-linux-x86_64-gnu.tar.gz"
root_name=${archive_name%.tar.gz}
manifest=$(tar --extract --to-stdout --gzip --file "$release_a/$archive_name" "$root_name/MANIFEST.tsv")
manifest_seal=$(printf '%s\n' "$manifest" | tail -n 1)
manifest_seal=${manifest_seal#seal$'\t'}

"$script_dir/render_s2_preview_provenance.sh" \
    "$release_a" "$source_commit" "$source_tree" "$manifest_seal" > /dev/null
"$script_dir/render_s2_preview_provenance.sh" \
    "$release_b" "$source_commit" "$source_tree" "$manifest_seal" > /dev/null
cmp -- "$release_a/PROVENANCE.tsv" "$release_b/PROVENANCE.tsv"
"$script_dir/verify_s2_preview_provenance.sh" \
    "$release_a" "$source_commit" "$source_tree" > /dev/null

wrong_source="$temp_root/wrong-source"
cp -a -- "$release_a" "$wrong_source"
if "$script_dir/verify_s2_preview_provenance.sh" \
    "$wrong_source" 3333333333333333333333333333333333333333 "$source_tree" \
    > /dev/null 2>&1; then
    echo "preview verifier accepted the wrong expected source commit" >&2
    exit 1
fi
if "$script_dir/verify_s2_preview_provenance.sh" \
    "$wrong_source" "$source_commit" 4444444444444444444444444444444444444444 \
    > /dev/null 2>&1; then
    echo "preview verifier accepted the wrong expected source tree" >&2
    exit 1
fi

mutated_asset="$temp_root/mutated-asset"
cp -a -- "$release_a" "$mutated_asset"
printf '\000' | dd of="$mutated_asset/$archive_name" bs=1 seek=0 conv=notrunc status=none
if "$script_dir/verify_s2_preview_provenance.sh" \
    "$mutated_asset" "$source_commit" "$source_tree" > /dev/null 2>&1; then
    echo "preview verifier accepted a mutated archive" >&2
    exit 1
fi

mutated_checksum="$temp_root/mutated-checksum"
cp -a -- "$release_a" "$mutated_checksum"
printf '# mutation\n' >> "$mutated_checksum/SHA256SUMS"
if "$script_dir/verify_s2_preview_provenance.sh" \
    "$mutated_checksum" "$source_commit" "$source_tree" > /dev/null 2>&1; then
    echo "preview verifier accepted a mutated checksum asset" >&2
    exit 1
fi

mutated_bootstrap="$temp_root/mutated-bootstrap"
cp -a -- "$release_a" "$mutated_bootstrap"
printf '\n# mutation\n' >> "$mutated_bootstrap/nauxup.sh"
if "$script_dir/verify_s2_preview_provenance.sh" \
    "$mutated_bootstrap" "$source_commit" "$source_tree" > /dev/null 2>&1; then
    echo "preview verifier accepted a mutated bootstrap asset" >&2
    exit 1
fi

mutated_seal="$temp_root/mutated-seal"
cp -a -- "$release_a" "$mutated_seal"
sed -i 's/^seal\t./seal\t0/' "$mutated_seal/PROVENANCE.tsv"
if "$script_dir/verify_s2_preview_provenance.sh" \
    "$mutated_seal" "$source_commit" "$source_tree" > /dev/null 2>&1; then
    echo "preview verifier accepted a mutated provenance seal" >&2
    exit 1
fi

extra="$temp_root/extra"
cp -a -- "$release_a" "$extra"
printf 'unowned\n' > "$extra/EXTRA"
if "$script_dir/verify_s2_preview_provenance.sh" \
    "$extra" "$source_commit" "$source_tree" > /dev/null 2>&1; then
    echo "preview verifier accepted an extra asset" >&2
    exit 1
fi

linked="$temp_root/linked"
cp -a -- "$release_a" "$linked"
rm -f -- "$linked/nauxup.sh"
ln -s -- "$release_a/nauxup.sh" "$linked/nauxup.sh"
if "$script_dir/verify_s2_preview_provenance.sh" \
    "$linked" "$source_commit" "$source_tree" > /dev/null 2>&1; then
    echo "preview verifier accepted a linked asset" >&2
    exit 1
fi

wrong_mode="$temp_root/wrong-mode"
cp -a -- "$release_a" "$wrong_mode"
chmod 0600 -- "$wrong_mode/PROVENANCE.tsv"
if "$script_dir/verify_s2_preview_provenance.sh" \
    "$wrong_mode" "$source_commit" "$source_tree" > /dev/null 2>&1; then
    echo "preview verifier accepted a noncanonical provenance mode" >&2
    exit 1
fi

if "$script_dir/render_s2_preview_provenance.sh" \
    "$temp_root/release-without-provenance" "$source_commit" "$source_tree" \
    0000000000000000000000000000000000000000000000000000000000000000 \
    > /dev/null 2>&1; then
    echo "preview producer accepted a false bundle manifest seal" >&2
    exit 1
fi

for policy in SECURITY.md COMPATIBILITY.md SUPPORT.md; do
    test -s "$repo_root/$policy"
done
grep -F 'security/advisories/new' "$repo_root/SECURITY.md" > /dev/null
grep -F 'naux run program.nx' "$repo_root/COMPATIBILITY.md" > /dev/null
grep -F -- '--engine vm' "$repo_root/SUPPORT.md" > /dev/null
test -s "$repo_root/.github/ISSUE_TEMPLATE/bug_report.yml"
test -s "$repo_root/.github/ISSUE_TEMPLATE/config.yml"

printf 'S2 preview provenance determinism: PASS\n'
printf 'S2 preview source/tree/all-assets/seal/inventory/link/mode mutation rejection: PASS\n'
printf 'S2 preview public policy presence: PASS\n'
