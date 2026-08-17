#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
binary=${1:-"$repo_root/target/debug/naux"}
source_file="$repo_root/naux-lang/examples/learn_prime_sum.nx"

if [[ ! -x "$binary" ]]; then
    echo "terminal-I/O carrier needs an executable NAUX binary: $binary" >&2
    exit 1
fi
if ! command -v script > /dev/null 2>&1; then
    echo "terminal-I/O carrier needs the util-linux script command" >&2
    exit 1
fi

temp_root=$(mktemp -d "${TMPDIR:-/tmp}/naux-s1-terminal.XXXXXXXX")
cleanup() {
    rm -rf -- "$temp_root"
}
trap cleanup EXIT

for engine in vm interp; do
    transcript="$temp_root/$engine.txt"
    command_line=$(printf '%q run %q --engine %q' "$binary" "$source_file" "$engine")
    printf '5\n2 4 5 7 8\n' \
        | script -qfec "$command_line" /dev/null \
        | tr -d '\r' > "$transcript"
    grep -F 'input> input> 14' "$transcript" > /dev/null
done

printf 'S1 terminal input VM/interpreter parity: PASS\n'
