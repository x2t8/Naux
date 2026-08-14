#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C
export TZ=UTC

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
package=$(awk -F '\t' '$1 == "package" { print $2; exit }' "$repo_root/distribution/s1-learn/windows/BUILD-SEED.tsv")
version=${package#naux@}
temp_root=$(mktemp -d "${TMPDIR:-/tmp}/naux-s1-windows-release-test.XXXXXXXX")
release_a="$temp_root/release-a"
release_b="$temp_root/release-b"
build_a="$temp_root/build-a"
build_b="$temp_root/build-b"
archive_name="naux-learn-$version-windows-x86_64-gnu.zip"
checksum_name="$archive_name.sha256"
root_name=${archive_name%.zip}

cleanup() {
    rm -rf -- "$temp_root"
}
trap cleanup EXIT

if [[ -z "${NAUX_WINDOWS_MINGW_BIN:-}" || -z "${NAUX_WINDOWS_ZIP:-}" ]]; then
    echo "set NAUX_WINDOWS_MINGW_BIN and NAUX_WINDOWS_ZIP to the pinned producer tools" >&2
    exit 2
fi

NAUX_WINDOWS_CARGO_TARGET_DIR="$build_a" \
    "$script_dir/package_s1_release_windows.sh" "$release_a"
NAUX_WINDOWS_CARGO_TARGET_DIR="$build_b" \
    "$script_dir/package_s1_release_windows.sh" "$release_b"

cmp -- "$build_a/x86_64-pc-windows-gnu/release/naux.exe" \
    "$build_b/x86_64-pc-windows-gnu/release/naux.exe"
cmp -- "$build_a/x86_64-pc-windows-gnu/release/naux-learn-setup.exe" \
    "$build_b/x86_64-pc-windows-gnu/release/naux-learn-setup.exe"
cmp -- "$release_a/$archive_name" "$release_b/$archive_name"
cmp -- "$release_a/$checksum_name" "$release_b/$checksum_name"
cmp -- "$release_a/RELEASE_NOTES.md" "$release_b/RELEASE_NOTES.md"
actual_inventory=$(find "$release_a" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort)
expected_inventory=$(printf '%s\n' RELEASE_NOTES.md "$archive_name" "$checksum_name" | sort)
if [[ "$actual_inventory" != "$expected_inventory" ]]; then
    echo "Windows release output inventory is not canonical" >&2
    exit 1
fi

mutation="$temp_root/mutation"
mkdir -m 0755 -- "$mutation"
cp -- "$release_a/$archive_name" "$mutation/$archive_name"
sed 's/^[0-9a-f]/X/' "$release_a/$checksum_name" > "$mutation/$checksum_name"
if "$script_dir/verify_s1_release_windows.sh" \
    "$mutation/$archive_name" "$mutation/$checksum_name" > /dev/null 2>&1; then
    echo "Windows release verifier accepted a corrupted checksum" >&2
    exit 1
fi

payload="$mutation/payload"
mkdir -m 0755 -- "$payload"
bsdtar --extract --file "$release_a/$archive_name" --directory "$payload" --no-same-owner
printf 'unsealed extra member\n' > "$payload/$root_name/EXTRA"
find "$payload/$root_name" -exec touch -h -d '@315532800' -- {} +
cat > "$mutation/extra-list" <<EOF
$root_name/
$root_name/BUILD-SEED.tsv
$root_name/HOST-DEPENDENCIES.tsv
$root_name/LICENSE
$root_name/MANIFEST.tsv
$root_name/README.md
$root_name/NAUX-Learn-Setup.exe
$root_name/EXTRA
$root_name/assets/
$root_name/assets/langnaux-learn.ico
$root_name/assets/langnaux-learn.png
$root_name/bin/
$root_name/bin/naux.exe
$root_name/docs/
$root_name/docs/LIMITATIONS.md
$root_name/docs/RELEASE_DISCLOSURE.md
$root_name/docs/s1_learn_batch_io.md
$root_name/docs/s1_learn_diagnostics.md
$root_name/docs/s1_learn_execution_envelope.md
$root_name/docs/s1_learn_quick_reference_v0_1.md
$root_name/examples/
$root_name/examples/hello.nx
$root_name/examples/hello.out
$root_name/locales/
$root_name/locales/SUPPORTED_LOCALES.tsv
$root_name/locales/de.tsv
$root_name/locales/en-US.tsv
$root_name/locales/es.tsv
$root_name/locales/fr.tsv
$root_name/locales/ja-JP.tsv
$root_name/locales/ko-KR.tsv
$root_name/locales/pt-BR.tsv
$root_name/locales/vi-VN.tsv
$root_name/locales/zh-CN.tsv
EOF
rm -f -- "$mutation/$archive_name" "$mutation/$checksum_name"
(
    cd -- "$payload"
    "$NAUX_WINDOWS_ZIP" -q -X -9 "$mutation/$archive_name" -@ < "$mutation/extra-list"
)
mutation_hash=$(sha256sum -- "$mutation/$archive_name" | awk '{print $1}')
printf '%s  %s\n' "$mutation_hash" "$archive_name" > "$mutation/$checksum_name"
if "$script_dir/verify_s1_release_windows.sh" \
    "$mutation/$archive_name" "$mutation/$checksum_name" > /dev/null 2>&1; then
    echo "Windows release verifier accepted a coherently checksummed extra member" >&2
    exit 1
fi

pe_mutation="$temp_root/pe-mutation"
pe_payload="$pe_mutation/payload"
mkdir -p -m 0755 -- "$pe_payload"
bsdtar --extract --file "$release_a/$archive_name" --directory "$pe_payload" --no-same-owner
pe_binary="$pe_payload/$root_name/bin/naux.exe"
pe_offset=$(od -An -tu4 -j 60 -N 4 -- "$pe_binary" | tr -d ' ')
timestamp_offset=$((pe_offset + 8))
printf '\001\000\000\000' | dd of="$pe_binary" bs=1 seek="$timestamp_offset" conv=notrunc status=none
new_binary_hash=$(sha256sum -- "$pe_binary" | awk '{print $1}')
manifest="$pe_payload/$root_name/MANIFEST.tsv"
body="$pe_mutation/manifest.body"
awk -F '\t' -v OFS='\t' -v digest="$new_binary_hash" '
    $1 == "seal" { next }
    $1 == "file" && $5 == "bin/naux.exe" { $4 = digest }
    { print }
' "$manifest" > "$body"
new_seal=$(
    {
        printf 'NAUX:s1-learn-bundle:manifest:v1\0'
        cat -- "$body"
    } | sha256sum | awk '{print $1}'
)
{
    cat -- "$body"
    printf 'seal\t%s\n' "$new_seal"
} > "$manifest"
chmod 0644 -- "$manifest"
find "$pe_payload/$root_name" -exec touch -h -d '@315532800' -- {} +
bsdtar --list --file "$release_a/$archive_name" > "$pe_mutation/list"
(
    cd -- "$pe_payload"
    "$NAUX_WINDOWS_ZIP" -q -X -9 "$pe_mutation/$archive_name" -@ < "$pe_mutation/list"
)
pe_mutation_hash=$(sha256sum -- "$pe_mutation/$archive_name" | awk '{print $1}')
printf '%s  %s\n' "$pe_mutation_hash" "$archive_name" > "$pe_mutation/$checksum_name"
if "$script_dir/verify_s1_release_windows.sh" \
    "$pe_mutation/$archive_name" "$pe_mutation/$checksum_name" > /dev/null 2>&1; then
    echo "Windows release verifier accepted a coherently resealed nonzero PE timestamp" >&2
    exit 1
fi

icon_mutation="$temp_root/icon-mutation.ico"
cp -- "$pe_payload/$root_name/assets/langnaux-learn.ico" "$icon_mutation"
icon_size=$(stat -c %s -- "$icon_mutation")
last_icon_byte=$(od -An -tu1 -j "$((icon_size - 1))" -N 1 -- "$icon_mutation" | tr -d ' ')
mutated_icon_byte=$((last_icon_byte ^ 1))
printf "\\$(printf '%03o' "$mutated_icon_byte")" | \
    dd of="$icon_mutation" bs=1 seek="$((icon_size - 1))" conv=notrunc status=none
if "$repo_root/target/release/naux" installation verify-windows-icon \
    "$pe_binary" "$icon_mutation" > /dev/null 2>&1; then
    echo "Windows icon verifier accepted a mutated canonical ICO" >&2
    exit 1
fi

printf 'S1 Windows release independent-build reproducibility: PASS\n'
printf 'S1 Windows release archive mutation rejection: PASS\n'
printf 'S1 Windows release PE/import mutation rejection: PASS\n'
printf 'S1 Windows release semantic icon mutation rejection: PASS\n'
