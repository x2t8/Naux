#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
temp_root=$(mktemp -d "${TMPDIR:-/tmp}/naux-s1-wp6.XXXXXXXX")
package=$(awk -F '\t' '$1 == "package" { print $2; exit }' "$repo_root/distribution/s1-learn/BUILD-SEED.tsv")
version=${package#naux@}
bundle="$temp_root/naux-learn-$version-linux-x86_64-gnu"
home="$temp_root/home"
prefix="$home/.local/share/naux/toolchains/learn/$version"
launcher_bin="$home/.local/bin"
poison="$temp_root/no-toolchain"

cleanup() {
    rm -rf -- "$temp_root"
}
trap cleanup EXIT

"$script_dir/package_s1_learn.sh" "$bundle"

mkdir -p -- "$poison" "$home"
install -m 0755 /bin/false "$poison/cargo"
install -m 0755 /bin/false "$poison/rustc"

env PATH="$poison" "$bundle/bin/naux" bundle verify "$bundle" > "$temp_root/verify.txt"
env HOME="$home" PATH="$poison" "$bundle/naux-learn-setup" --yes --language vi-VN \
    > "$temp_root/install.txt"
env HOME="$home" PATH="$launcher_bin:$poison" naux run \
    "$repo_root/distribution/s1-learn/hello.nx" \
    > "$temp_root/hello.actual"

cmp -- "$repo_root/distribution/s1-learn/hello.out" "$temp_root/hello.actual"
grep -Fx 'status: verified' "$temp_root/verify.txt" > /dev/null
test -L "$launcher_bin/naux"
test -L "$launcher_bin/nauxup"
env HOME="$home" PATH="$launcher_bin:$poison" nauxup doctor > /dev/null
env HOME="$home" PATH="$launcher_bin:$poison" nauxup uninstall --dry-run > /dev/null

if env HOME="$home" PATH="$poison" "$bundle/naux-learn-setup" --yes --language vi-VN \
    > "$temp_root/reinstall.out" 2> "$temp_root/reinstall.err"; then
    echo "installer unexpectedly overwrote an existing prefix" >&2
    exit 1
fi
grep -F 'already exists' "$temp_root/reinstall.err" > /dev/null

env HOME="$home" PATH="$launcher_bin:$poison" nauxup uninstall --yes > "$temp_root/uninstall.txt"
test ! -e "$prefix"
test ! -e "$launcher_bin/naux"
test ! -e "$launcher_bin/nauxup"

printf 'S1-WP6 no-toolchain native-setup/run/uninstall: PASS\n'
