#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
temp_root=$(mktemp -d "${TMPDIR:-/tmp}/naux-s1-wp6.XXXXXXXX")
bundle="$temp_root/naux-learn-0.1.0-linux-x86_64-gnu"
prefix="$temp_root/installed"
poison="$temp_root/no-toolchain"
state="$temp_root/state"

cleanup() {
    rm -rf -- "$temp_root"
}
trap cleanup EXIT

"$script_dir/package_s1_learn.sh" "$bundle"

mkdir -p -- "$poison" "$state"
install -m 0755 /bin/false "$poison/cargo"
install -m 0755 /bin/false "$poison/rustc"

env PATH="$poison" "$bundle/bin/naux" bundle verify "$bundle" > "$temp_root/verify.txt"
env PATH="$poison" "$bundle/naux-learn-setup" --yes --language vi-VN \
    --prefix "$prefix" --state-directory "$state" \
    > "$temp_root/install.txt"
env PATH="$poison" "$prefix/bin/naux" run "$prefix/examples/hello.nx" \
    > "$temp_root/hello.actual"

cmp -- "$prefix/examples/hello.out" "$temp_root/hello.actual"
grep -Fx 'status: verified' "$temp_root/verify.txt" > /dev/null
receipt=$(sed -n 's/^receipt: //p' "$temp_root/install.txt")
test -f "$receipt"
env PATH="$poison" "$prefix/bin/naux" installation uninstall --receipt "$receipt" --dry-run \
    > "$temp_root/uninstall-dry-run.txt"
grep -Fx 'status: uninstall-planned' "$temp_root/uninstall-dry-run.txt" > /dev/null

if env PATH="$poison" "$bundle/naux-learn-setup" --yes --language vi-VN \
    --prefix "$prefix" --state-directory "$state" \
    > "$temp_root/reinstall.out" 2> "$temp_root/reinstall.err"; then
    echo "installer unexpectedly overwrote an existing prefix" >&2
    exit 1
fi
grep -F 'already exists' "$temp_root/reinstall.err" > /dev/null

env PATH="$poison" "$prefix/bin/naux" installation uninstall --receipt "$receipt" \
    > "$temp_root/uninstall.txt"
test ! -e "$prefix"
test ! -e "$receipt"

printf 'S1-WP6 no-toolchain native-setup/run/uninstall: PASS\n'
