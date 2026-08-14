#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C
export TZ=UTC

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
seed_file="$repo_root/distribution/s1-learn/windows/BUILD-SEED.tsv"
release_notes="$repo_root/distribution/s1-learn/windows/RELEASE_NOTES.md"

if [[ $# -gt 1 ]]; then
    echo "usage: scripts/package_s1_release_windows.sh [new-output-directory]" >&2
    exit 2
fi

package=$(awk -F '\t' '$1 == "package" { if (found++) exit 3; print $2 } END { if (!found) exit 4 }' "$seed_file")
version=${package#naux@}
if [[ "$package" != "naux@$version" || ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Windows build seed contains a noncanonical package identity" >&2
    exit 1
fi

root_name="naux-learn-$version-windows-x86_64-gnu"
archive_name="$root_name.zip"
checksum_name="$archive_name.sha256"
output=${1:-"$repo_root/target/releases/naux-learn-$version-windows"}
output_parent=$(dirname -- "$output")
output_leaf=$(basename -- "$output")
if [[ -z "$output_leaf" || "$output_leaf" == "." || "$output_leaf" == ".." || "$output" == "/" ]]; then
    echo "refusing unsafe Windows release output path: $output" >&2
    exit 2
fi
if [[ -e "$output" || -L "$output" ]]; then
    echo "Windows release output path already exists: $output" >&2
    exit 2
fi

zip_command=${NAUX_WINDOWS_ZIP:-}
if [[ -z "$zip_command" ]]; then
    zip_command=$(command -v zip || true)
fi
if [[ -z "$zip_command" || ! -x "$zip_command" ]]; then
    echo "set NAUX_WINDOWS_ZIP to the pinned Info-ZIP 3.0 executable" >&2
    exit 1
fi
expected_zip_hash=$(awk -F '\t' '$1 == "archive-producer-executable-sha256" { if (found++) exit 3; print $2 } END { if (!found) exit 4 }' "$seed_file")
actual_zip_hash=$(sha256sum -- "$zip_command" | awk '{print $1}')
if [[ ! "$expected_zip_hash" =~ ^[0-9a-f]{64}$ \
    || "$actual_zip_hash" != "$expected_zip_hash" ]]; then
    echo "Windows release producer requires the pinned Info-ZIP executable" >&2
    exit 1
fi
if ! "$zip_command" -v | grep -F "This is Zip 3.0" > /dev/null; then
    echo "Windows release producer requires Info-ZIP 3.0" >&2
    exit 1
fi
for command in bsdtar sha256sum touch; do
    if ! command -v "$command" > /dev/null 2>&1; then
        echo "required Windows release command is missing: $command" >&2
        exit 1
    fi
done
if ! grep -Fx "# NAUX Learn $version for Windows" "$release_notes" > /dev/null; then
    echo "Windows release notes version does not match $version" >&2
    exit 1
fi

mkdir -p -- "$output_parent"
output_parent=$(CDPATH= cd -- "$output_parent" && pwd)
output="$output_parent/$output_leaf"
staging=$(mktemp -d "$output_parent/.naux-s1-windows-release.XXXXXXXX")
result="$staging/result"
payload="$staging/payload"
list="$staging/inventory.txt"
cleanup() {
    rm -rf -- "$staging"
}
trap cleanup EXIT
mkdir -m 0755 -- "$result" "$payload"

"$script_dir/package_s1_learn_windows.sh" "$payload/$root_name"
find "$payload/$root_name" -type d -exec chmod 0755 -- {} +
find "$payload/$root_name" -exec touch -h -d '@315532800' -- {} +

cat > "$list" <<EOF
$root_name/
$root_name/BUILD-SEED.tsv
$root_name/HOST-DEPENDENCIES.tsv
$root_name/LICENSE
$root_name/MANIFEST.tsv
$root_name/README.md
$root_name/NAUX-Learn-Setup.exe
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
(
    cd -- "$payload"
    "$zip_command" -q -X -9 "$result/$archive_name" -@ < "$list"
)
chmod 0644 -- "$result/$archive_name"

archive_hash=$(sha256sum -- "$result/$archive_name" | awk '{print $1}')
printf '%s  %s\n' "$archive_hash" "$archive_name" > "$result/$checksum_name"
chmod 0644 -- "$result/$checksum_name"
install -m 0644 -- "$release_notes" "$result/RELEASE_NOTES.md"

NAUX_WINDOWS_ZIP="$zip_command" \
    "$script_dir/verify_s1_release_windows.sh" \
    "$result/$archive_name" \
    "$result/$checksum_name"

mv -- "$result" "$output"
trap - EXIT
rm -rf -- "$staging"
printf 'release-directory: %s\n' "$output"
printf 'archive: %s\n' "$archive_name"
printf 'archive-sha256: %s\n' "$archive_hash"
