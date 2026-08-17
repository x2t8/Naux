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
home="$temp_root/home"
bad_home="$temp_root/bad-home"

cleanup() {
    rm -rf -- "$temp_root"
}
trap cleanup EXIT

"$script_dir/package_s1_release.sh" "$release_a"
"$script_dir/package_s1_release.sh" "$release_b"

archive_name="naux-learn-$version-linux-x86_64-gnu.tar.gz"
checksum_name="SHA256SUMS"
cmp -- "$release_a/$archive_name" "$release_b/$archive_name"
cmp -- "$release_a/$checksum_name" "$release_b/$checksum_name"
cmp -- "$release_a/nauxup.sh" "$release_b/nauxup.sh"
actual_inventory=$(find "$release_a" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort)
expected_inventory=$(printf '%s\n' nauxup.sh "$archive_name" "$checksum_name" | sort)
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

mkdir -m 0755 -- "$poison" "$extract" "$home" "$bad_home"
install -m 0755 /bin/false "$poison/cargo"
install -m 0755 /bin/false "$poison/rustc"
cat > "$poison/curl" <<'EOF'
#!/usr/bin/env sh
set -eu
output=''
url=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output)
            shift
            [ "$#" -gt 0 ] || exit 2
            output=$1
            ;;
        https://*) url=$1 ;;
    esac
    shift
done
[ -n "$output" ] && [ -n "$url" ] || exit 2
asset=${url##*/}
case "$asset" in
    naux-learn-*.tar.gz|SHA256SUMS) ;;
    *) exit 2 ;;
esac
[ "$url" = "https://github.com/x2t8/Naux/releases/download/$NAUX_TEST_RELEASE_TAG/$asset" ] \
    || exit 2
cp -- "$NAUX_TEST_RELEASE_DIR/$asset" "$output"
EOF
chmod 0755 -- "$poison/curl"

bad_release="$temp_root/bad-release"
mkdir -m 0755 -- "$bad_release"
cp -- "$release_a/$archive_name" "$bad_release/$archive_name"
cp -- "$release_a/$checksum_name" "$bad_release/$checksum_name"
printf '\000' | dd of="$bad_release/$archive_name" bs=1 seek=0 conv=notrunc status=none
if env HOME="$bad_home" PATH="$poison:/usr/bin:/bin" NAUX_TEST_RELEASE_DIR="$bad_release" \
    NAUX_TEST_RELEASE_TAG="v$version-learn" \
    sh "$release_a/nauxup.sh" --yes --language en-US > /dev/null 2>&1; then
    echo "pinned bootstrap accepted a mutated archive" >&2
    exit 1
fi
test ! -e "$bad_home/.local/share/naux/toolchains/learn/$version"

env HOME="$home" PATH="$poison:/usr/bin:/bin" NAUX_TEST_RELEASE_DIR="$release_a" \
    NAUX_TEST_RELEASE_TAG="v$version-learn" \
    sh "$release_a/nauxup.sh" --yes --language en-US > "$temp_root/install.txt"
prefix="$home/.local/share/naux/toolchains/learn/$version"
launcher_bin="$home/.local/bin"
activation="$home/.local/state/naux/receipts/learn-$version.tsv"
test -L "$launcher_bin/naux"
test -L "$launcher_bin/nauxup"
test -f "$activation"
env HOME="$home" PATH="$launcher_bin:$poison:/usr/bin:/bin" \
    naux --version > "$temp_root/version.actual"
printf 'naux %s\n' "$version" > "$temp_root/version.expected"
cmp -- "$temp_root/version.expected" "$temp_root/version.actual"
env HOME="$home" PATH="$launcher_bin:$poison:/usr/bin:/bin" \
    naux run "$repo_root/distribution/s1-learn/hello.nx" > "$temp_root/hello.actual"
cmp -- "$repo_root/distribution/s1-learn/hello.out" "$temp_root/hello.actual"
env HOME="$home" PATH="$launcher_bin:$poison:/usr/bin:/bin" \
    nauxup doctor > /dev/null
env HOME="$home" PATH="$launcher_bin:$poison:/usr/bin:/bin" \
    nauxup uninstall --dry-run > /dev/null
env HOME="$home" PATH="$launcher_bin:$poison:/usr/bin:/bin" \
    nauxup uninstall --yes > /dev/null
test ! -e "$prefix"
test ! -e "$launcher_bin/naux"
test ! -e "$launcher_bin/nauxup"
test ! -e "$activation"

printf 'S1 release byte-reproducibility: PASS\n'
printf 'S1 release outer mutation rejection: PASS\n'
printf 'S1 release pinned-bootstrap mutation rejection: PASS\n'
printf 'S1 release clean-home/no-toolchain setup/launch/doctor/uninstall: PASS\n'
