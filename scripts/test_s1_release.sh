#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
package=$(awk -F '\t' '$1 == "package" { print $2; exit }' "$repo_root/distribution/s1-learn/BUILD-SEED.tsv")
version=${package#naux@}
temp_root=$(mktemp -d "${TMPDIR:-/tmp}/naux-s1-release-test.XXXXXXXX")
release_a="$temp_root/release-a"
release_b="$temp_root/release-b"
poison="$temp_root/no-toolchain"
extract="$temp_root/extract"
prefix="$temp_root/installed"
state="$temp_root/state"

cleanup() {
    rm -rf -- "$temp_root"
}
trap cleanup EXIT

"$script_dir/package_s1_release.sh" "$release_a"
"$script_dir/package_s1_release.sh" "$release_b"

archive_name="naux-learn-$version-linux-x86_64-gnu.tar.gz"
checksum_name="$archive_name.sha256"
cmp -- "$release_a/$archive_name" "$release_b/$archive_name"
cmp -- "$release_a/$checksum_name" "$release_b/$checksum_name"
cmp -- "$release_a/RELEASE_NOTES.md" "$release_b/RELEASE_NOTES.md"
actual_inventory=$(find "$release_a" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort)
expected_inventory=$(printf '%s\n' RELEASE_NOTES.md "$archive_name" "$checksum_name" | sort)
if [[ "$actual_inventory" != "$expected_inventory" ]]; then
    echo "release output inventory is not canonical" >&2
    exit 1
fi

"$script_dir/verify_s1_release.sh" \
    "$release_a/$archive_name" \
    "$release_a/$checksum_name"

mutation="$temp_root/mutation"
mkdir -m 0755 -- "$mutation"
cp -- "$release_a/$archive_name" "$mutation/$archive_name"
sed 's/^[0-9a-f]/X/' "$release_a/$checksum_name" > "$mutation/$checksum_name"
if "$script_dir/verify_s1_release.sh" \
    "$mutation/$archive_name" "$mutation/$checksum_name" > /dev/null 2>&1; then
    echo "release verifier accepted a corrupted checksum" >&2
    exit 1
fi

rm -f -- "$mutation/$archive_name" "$mutation/$checksum_name"
mkdir -m 0755 -- "$mutation/payload"
tar --extract --gzip --file "$release_a/$archive_name" --directory "$mutation/payload" --no-same-owner
printf 'unsealed extra member\n' > "$mutation/payload/${archive_name%.tar.gz}/EXTRA"
tar \
    --sort=name --format=ustar --mtime=@0 --owner=0 --group=0 --numeric-owner \
    --directory "$mutation/payload" --create --file - "${archive_name%.tar.gz}" \
    | gzip --no-name --best > "$mutation/$archive_name"
mutation_hash=$(sha256sum -- "$mutation/$archive_name" | awk '{print $1}')
printf '%s  %s\n' "$mutation_hash" "$archive_name" > "$mutation/$checksum_name"
if "$script_dir/verify_s1_release.sh" \
    "$mutation/$archive_name" "$mutation/$checksum_name" > /dev/null 2>&1; then
    echo "release verifier accepted a coherently checksummed extra member" >&2
    exit 1
fi

mkdir -m 0755 -- "$poison" "$extract" "$state"
install -m 0755 /bin/false "$poison/cargo"
install -m 0755 /bin/false "$poison/rustc"
tar --extract --gzip --file "$release_a/$archive_name" --directory "$extract" --no-same-owner
bundle="$extract/${archive_name%.tar.gz}"

env PATH="$poison:/usr/bin:/bin" \
    "$bundle/naux-learn-setup" --yes --language en-US --prefix "$prefix" \
    --state-directory "$state" > "$temp_root/install.txt"
receipt=$(sed -n 's/^receipt: //p' "$temp_root/install.txt")
env PATH="$poison:/usr/bin:/bin" \
    "$prefix/bin/naux" run "$prefix/examples/hello.nx" > "$temp_root/hello.actual"
cmp -- "$prefix/examples/hello.out" "$temp_root/hello.actual"
env PATH="$poison:/usr/bin:/bin" \
    "$prefix/bin/naux" installation uninstall --receipt "$receipt" --dry-run > /dev/null
env PATH="$poison:/usr/bin:/bin" \
    "$prefix/bin/naux" installation uninstall --receipt "$receipt" > /dev/null
test ! -e "$prefix"
test ! -e "$receipt"

printf 'S1 release byte-reproducibility: PASS\n'
printf 'S1 release outer mutation rejection: PASS\n'
printf 'S1 release no-toolchain native-setup/run/uninstall: PASS\n'
