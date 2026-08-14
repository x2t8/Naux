#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
source_dir="$repo_root/distribution/s1-learn"
seed_file="$source_dir/BUILD-SEED.tsv"
locale_files=(SUPPORTED_LOCALES.tsv de.tsv en-US.tsv es.tsv fr.tsv ja-JP.tsv ko-KR.tsv pt-BR.tsv vi-VN.tsv zh-CN.tsv)

if [[ $# -gt 1 ]]; then
    echo "usage: scripts/package_s1_learn.sh [new-output-directory]" >&2
    exit 2
fi

expected_package=$(awk -F '\t' '$1 == "package" { if (found++) exit 3; print $2 } END { if (!found) exit 4 }' "$seed_file")
version=${expected_package#naux@}
if [[ "$expected_package" != "naux@$version" || ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "build seed contains a noncanonical package identity" >&2
    exit 1
fi

output=${1:-"$repo_root/target/dist/naux-learn-$version-linux-x86_64-gnu"}
output_parent=$(dirname -- "$output")
output_leaf=$(basename -- "$output")
if [[ -z "$output_leaf" || "$output_leaf" == "." || "$output_leaf" == ".." || "$output" == "/" ]]; then
    echo "refusing unsafe output path: $output" >&2
    exit 2
fi
if [[ -e "$output" || -L "$output" ]]; then
    echo "output path already exists: $output" >&2
    exit 2
fi

mkdir -p -- "$output_parent"
staging="$output_parent/.$output_leaf.staging-$$"
manifest_body="$output_parent/.$output_leaf.manifest-$$"
if [[ -e "$staging" || -L "$staging" || -e "$manifest_body" || -L "$manifest_body" ]]; then
    echo "staging path already exists" >&2
    exit 2
fi

cleanup() {
    rm -rf -- "$staging"
    rm -f -- "$manifest_body"
}
trap cleanup EXIT

seed_value() {
    local key=$1
    awk -F '\t' -v key="$key" '$1 == key { if (found++) exit 3; print $2 } END { if (!found) exit 4 }' "$seed_file"
}

if [[ $(head -n 1 -- "$seed_file") != $'NAUX-S1-BUILD-SEED\t1' ]]; then
    echo "build seed magic/version mismatch" >&2
    exit 1
fi

expected_rustc_release=$(seed_value rustc-release)
expected_rustc_commit=$(seed_value rustc-commit)
expected_cargo_release=$(seed_value cargo-release)
expected_cargo_commit=$(seed_value cargo-commit)
expected_host=$(seed_value host)
expected_lock_hash=$(seed_value cargo-lock-sha256)
expected_package=$(seed_value package)
expected_brand_hash=$(seed_value brand-source-sha256)
expected_locale_hash=$(seed_value installer-locale-set-sha256)

actual_rustc_release=$(rustc -vV | sed -n 's/^release: //p')
actual_rustc_commit=$(rustc -vV | sed -n 's/^commit-hash: //p')
actual_host=$(rustc -vV | sed -n 's/^host: //p')
actual_cargo_release=$(cargo -V | sed -n 's/^cargo \([^ ]*\) .*/\1/p')
actual_cargo_commit=$(cargo -V | sed -n 's/^cargo [^ ]* (\([^ ]*\) .*/\1/p')
actual_lock_hash=$(sha256sum -- "$repo_root/Cargo.lock" | awk '{print $1}')
actual_brand_hash=$(sha256sum -- "$repo_root/assets/langnaux-learn.png" | awk '{print $1}')
actual_locale_hash=$(
    cd -- "$repo_root/naux-lang/locales"
    for locale_file in "${locale_files[@]}"; do
        sha256sum -- "$locale_file"
    done | sha256sum | awk '{print $1}'
)
actual_package_version=$(awk '
    /^\[package\]$/ { in_package = 1; next }
    /^\[/ { in_package = 0 }
    in_package && /^version[[:space:]]*=/ {
        line = $0
        sub(/^[^"]*"/, "", line)
        sub(/".*/, "", line)
        print line
        exit
    }
' "$repo_root/naux-lang/Cargo.toml")

if [[ "$actual_rustc_release" != "$expected_rustc_release" \
    || "$actual_rustc_commit" != "$expected_rustc_commit" \
    || "$actual_cargo_release" != "$expected_cargo_release" \
    || "$actual_cargo_commit" != "$expected_cargo_commit" \
    || "$actual_host" != "$expected_host" \
    || "$actual_lock_hash" != "$expected_lock_hash" \
    || "$actual_brand_hash" != "$expected_brand_hash" \
    || "$actual_locale_hash" != "$expected_locale_hash" \
    || "naux@$actual_package_version" != "$expected_package" ]]; then
    echo "active build seed does not match distribution/s1-learn/BUILD-SEED.tsv" >&2
    exit 1
fi

if [[ $(uname -s) != "Linux" || $(uname -m) != "x86_64" ]]; then
    echo "S1-WP6 packaging requires Linux x86-64" >&2
    exit 1
fi

(
    cd -- "$repo_root"
    env \
        -u CARGO_BUILD_RUSTC_WRAPPER \
        -u CARGO_BUILD_RUSTFLAGS \
        -u CARGO_ENCODED_RUSTFLAGS \
        -u CARGO_PROFILE_RELEASE_CODEGEN_UNITS \
        -u CARGO_PROFILE_RELEASE_DEBUG \
        -u CARGO_PROFILE_RELEASE_INCREMENTAL \
        -u CARGO_PROFILE_RELEASE_LTO \
        -u CARGO_PROFILE_RELEASE_OPT_LEVEL \
        -u CARGO_PROFILE_RELEASE_PANIC \
        -u CARGO_PROFILE_RELEASE_STRIP \
        -u CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS \
        -u RUSTC_WORKSPACE_WRAPPER \
        -u RUSTC_WRAPPER \
        -u RUSTFLAGS \
        CARGO_INCREMENTAL=0 \
        CARGO_TARGET_DIR="$repo_root/target" \
        cargo build --locked --release -p naux \
            --bin naux \
            --bin naux-learn-setup \
            --bin nauxup
)

binary="$repo_root/target/release/naux"
setup_binary="$repo_root/target/release/naux-learn-setup"
nauxup_binary="$repo_root/target/release/nauxup"
binary_version=$("$binary" --version)
setup_version=$("$setup_binary" --help | sed -n '1p')
nauxup_version=$("$nauxup_binary" --version)
interpreter=$(readelf -l -- "$binary" | sed -n 's/.*Requesting program interpreter: \([^]]*\).*/\1/p')
setup_interpreter=$(readelf -l -- "$setup_binary" | sed -n 's/.*Requesting program interpreter: \([^]]*\).*/\1/p')
nauxup_interpreter=$(readelf -l -- "$nauxup_binary" | sed -n 's/.*Requesting program interpreter: \([^]]*\).*/\1/p')
needed=$(readelf -d -- "$binary" | sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' | sort)
setup_needed=$(readelf -d -- "$setup_binary" | sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' | sort)
nauxup_needed=$(readelf -d -- "$nauxup_binary" | sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' | sort)
expected_needed=$'ld-linux-x86-64.so.2\nlibc.so.6\nlibgcc_s.so.1\nlibm.so.6'
expected_setup_needed=$'ld-linux-x86-64.so.2\nlibc.so.6\nlibgcc_s.so.1'
max_glibc=$(readelf --version-info -- "$binary" | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -n 1)
max_gcc=$(readelf --version-info -- "$binary" | grep -o 'GCC_[0-9.]*' | sort -Vu | tail -n 1)
setup_max_glibc=$(readelf --version-info -- "$setup_binary" | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -n 1)
setup_max_gcc=$(readelf --version-info -- "$setup_binary" | grep -o 'GCC_[0-9.]*' | sort -Vu | tail -n 1)
nauxup_max_glibc=$(readelf --version-info -- "$nauxup_binary" | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -n 1)
nauxup_max_gcc=$(readelf --version-info -- "$nauxup_binary" | grep -o 'GCC_[0-9.]*' | sort -Vu | tail -n 1)
machine=$(readelf -h -- "$binary" | sed -n 's/^  Machine:[[:space:]]*//p')
elf_type=$(readelf -h -- "$binary" | sed -n 's/^  Type:[[:space:]]*\([^ ]*\).*/\1/p')
setup_machine=$(readelf -h -- "$setup_binary" | sed -n 's/^  Machine:[[:space:]]*//p')
setup_elf_type=$(readelf -h -- "$setup_binary" | sed -n 's/^  Type:[[:space:]]*\([^ ]*\).*/\1/p')
nauxup_machine=$(readelf -h -- "$nauxup_binary" | sed -n 's/^  Machine:[[:space:]]*//p')
nauxup_elf_type=$(readelf -h -- "$nauxup_binary" | sed -n 's/^  Type:[[:space:]]*\([^ ]*\).*/\1/p')

if [[ "$interpreter" != "/lib64/ld-linux-x86-64.so.2" \
    || "$setup_interpreter" != "/lib64/ld-linux-x86-64.so.2" \
    || "$nauxup_interpreter" != "/lib64/ld-linux-x86-64.so.2" \
    || "$binary_version" != "naux $version" \
    || "$setup_version" != "NAUX Learn Setup $version" \
    || "$nauxup_version" != "nauxup $version" \
    || "$needed" != "$expected_needed" \
    || "$setup_needed" != "$expected_setup_needed" \
    || "$nauxup_needed" != "$expected_setup_needed" \
    || "$max_glibc" != "GLIBC_2.39" \
    || "$max_gcc" != "GCC_4.2.0" \
    || "$setup_max_glibc" != "GLIBC_2.34" \
    || "$setup_max_gcc" != "GCC_4.2.0" \
    || "$nauxup_max_glibc" != "GLIBC_2.34" \
    || "$nauxup_max_gcc" != "GCC_4.2.0" \
    || "$machine" != "Advanced Micro Devices X86-64" \
    || "$setup_machine" != "Advanced Micro Devices X86-64" \
    || "$nauxup_machine" != "Advanced Micro Devices X86-64" \
    || "$elf_type" != "DYN" \
    || "$setup_elf_type" != "DYN" \
    || "$nauxup_elf_type" != "DYN" ]]; then
    echo "release binary dynamic host boundary differs from HOST-DEPENDENCIES.tsv" >&2
    exit 1
fi

mkdir -p -- "$staging/assets" "$staging/bin" "$staging/docs" "$staging/examples" "$staging/locales"
chmod 0755 -- "$staging" "$staging/assets" "$staging/bin" "$staging/docs" "$staging/examples" "$staging/locales"
install -m 0644 -- "$source_dir/BUILD-SEED.tsv" "$staging/BUILD-SEED.tsv"
install -m 0644 -- "$source_dir/HOST-DEPENDENCIES.tsv" "$staging/HOST-DEPENDENCIES.tsv"
install -m 0644 -- "$repo_root/LICENSE" "$staging/LICENSE"
sed 's#../../assets/langnaux-learn.png#assets/langnaux-learn.png#' \
    "$source_dir/README.md" > "$staging/README.md"
chmod 0644 -- "$staging/README.md"
install -m 0755 -- "$setup_binary" "$staging/naux-learn-setup"
install -m 0644 -- "$repo_root/assets/langnaux-learn.png" "$staging/assets/langnaux-learn.png"
install -m 0755 -- "$binary" "$staging/bin/naux"
install -m 0755 -- "$nauxup_binary" "$staging/bin/nauxup"
install -m 0644 -- "$source_dir/LIMITATIONS.md" "$staging/docs/LIMITATIONS.md"
install -m 0644 -- "$source_dir/RELEASE_DISCLOSURE.md" "$staging/docs/RELEASE_DISCLOSURE.md"
install -m 0644 -- "$repo_root/docs/s1_learn_batch_io.md" "$staging/docs/s1_learn_batch_io.md"
install -m 0644 -- "$repo_root/docs/s1_learn_diagnostics.md" "$staging/docs/s1_learn_diagnostics.md"
install -m 0644 -- "$repo_root/docs/s1_learn_execution_envelope.md" "$staging/docs/s1_learn_execution_envelope.md"
install -m 0644 -- "$repo_root/docs/s1_learn_quick_reference_v0_1.md" "$staging/docs/s1_learn_quick_reference_v0_1.md"
install -m 0644 -- "$source_dir/hello.nx" "$staging/examples/hello.nx"
install -m 0644 -- "$source_dir/hello.out" "$staging/examples/hello.out"
for locale_file in "${locale_files[@]}"; do
    install -m 0644 -- "$repo_root/naux-lang/locales/$locale_file" "$staging/locales/$locale_file"
done

files=(
    BUILD-SEED.tsv
    HOST-DEPENDENCIES.tsv
    LICENSE
    README.md
    naux-learn-setup
    assets/langnaux-learn.png
    bin/naux
    bin/nauxup
    docs/LIMITATIONS.md
    docs/RELEASE_DISCLOSURE.md
    docs/s1_learn_batch_io.md
    docs/s1_learn_diagnostics.md
    docs/s1_learn_execution_envelope.md
    docs/s1_learn_quick_reference_v0_1.md
    examples/hello.nx
    examples/hello.out
    locales/SUPPORTED_LOCALES.tsv
    locales/de.tsv
    locales/en-US.tsv
    locales/es.tsv
    locales/fr.tsv
    locales/ja-JP.tsv
    locales/ko-KR.tsv
    locales/pt-BR.tsv
    locales/vi-VN.tsv
    locales/zh-CN.tsv
)
modes=(0644 0644 0644 0644 0755 0644 0755 0755 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644)

{
    printf 'NAUX-S1-LEARN-BUNDLE\t1\n'
    printf 'bundle\t%s\n' "$version"
    printf 'target\tlinux-x86_64-gnu\n'
    for index in "${!files[@]}"; do
        path=${files[$index]}
        size=$(stat -c %s -- "$staging/$path")
        digest=$(sha256sum -- "$staging/$path" | awk '{print $1}')
        printf 'file\t%s\t%s\t%s\t%s\n' "${modes[$index]}" "$size" "$digest" "$path"
    done
} > "$manifest_body"

seal=$(
    {
        printf 'NAUX:s1-learn-bundle:manifest:v1\0'
        cat -- "$manifest_body"
    } | sha256sum | awk '{print $1}'
)
{
    cat -- "$manifest_body"
    printf 'seal\t%s\n' "$seal"
} > "$staging/MANIFEST.tsv"
chmod 0644 -- "$staging/MANIFEST.tsv"
rm -f -- "$manifest_body"

"$staging/bin/naux" bundle verify "$staging"
mv -- "$staging" "$output"
trap - EXIT

printf 'bundle: %s\n' "$output"
printf 'manifest-seal: %s\n' "$seal"
