#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C
export TZ=UTC

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
source_dir="$repo_root/distribution/s1-learn/windows"
seed_file="$source_dir/BUILD-SEED.tsv"
locale_files=(SUPPORTED_LOCALES.tsv de.tsv en-US.tsv es.tsv fr.tsv ja-JP.tsv ko-KR.tsv pt-BR.tsv vi-VN.tsv zh-CN.tsv)

if [[ $# -gt 1 ]]; then
    echo "usage: scripts/package_s1_learn_windows.sh [new-output-directory]" >&2
    exit 2
fi

seed_value() {
    local key=$1
    awk -F '\t' -v key="$key" '$1 == key { if (found++) exit 3; print $2 } END { if (!found) exit 4 }' "$seed_file"
}

if [[ $(head -n 1 -- "$seed_file") != $'NAUX-S1-WINDOWS-BUILD-SEED\t1' ]]; then
    echo "Windows build seed magic/version mismatch" >&2
    exit 1
fi

expected_package=$(seed_value package)
version=${expected_package#naux@}
if [[ "$expected_package" != "naux@$version" || ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Windows build seed contains a noncanonical package identity" >&2
    exit 1
fi

output=${1:-"$repo_root/target/dist/naux-learn-$version-windows-x86_64-gnu"}
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

mingw_bin=${NAUX_WINDOWS_MINGW_BIN:-}
if [[ -z "$mingw_bin" ]]; then
    gcc_path=$(command -v x86_64-w64-mingw32-gcc || true)
    if [[ -n "$gcc_path" ]]; then
        mingw_bin=$(dirname -- "$gcc_path")
    fi
fi
if [[ -z "$mingw_bin" || ! -d "$mingw_bin" ]]; then
    echo "set NAUX_WINDOWS_MINGW_BIN to the directory containing the pinned MinGW-w64 tools" >&2
    exit 1
fi
mingw_bin=$(CDPATH= cd -- "$mingw_bin" && pwd)
gcc="$mingw_bin/x86_64-w64-mingw32-gcc"
objdump="$mingw_bin/x86_64-w64-mingw32-objdump"
windres="$mingw_bin/x86_64-w64-mingw32-windres"
for command in cargo od rustc sha256sum stat "$gcc" "$objdump" "$windres"; do
    if ! command -v "$command" > /dev/null 2>&1; then
        echo "required Windows producer command is missing: $command" >&2
        exit 1
    fi
done

expected_rustc_release=$(seed_value rustc-release)
expected_rustc_commit=$(seed_value rustc-commit)
expected_cargo_release=$(seed_value cargo-release)
expected_cargo_commit=$(seed_value cargo-commit)
expected_host=$(seed_value build-host)
expected_target=$(seed_value rust-target)
expected_lock_hash=$(seed_value cargo-lock-sha256)
expected_gcc_package=$(seed_value mingw-gcc-package)
expected_gcc_release=$(seed_value mingw-gcc-release)
expected_binutils_package=$(seed_value mingw-binutils-package)
expected_objdump_release=$(seed_value mingw-objdump-release)
expected_epoch=$(seed_value source-date-epoch)
expected_timestamp_policy=$(seed_value linker-timestamp-policy)
expected_brand_hash=$(seed_value brand-source-sha256)
expected_icon_hash=$(seed_value windows-icon-source-sha256)
expected_locale_hash=$(seed_value installer-locale-set-sha256)

actual_rustc_release=$(rustc -vV | sed -n 's/^release: //p')
actual_rustc_commit=$(rustc -vV | sed -n 's/^commit-hash: //p')
actual_host=$(rustc -vV | sed -n 's/^host: //p')
actual_cargo_release=$(cargo -V | sed -n 's/^cargo \([^ ]*\) .*/\1/p')
actual_cargo_commit=$(cargo -V | sed -n 's/^cargo [^ ]* (\([^ ]*\) .*/\1/p')
actual_lock_hash=$(sha256sum -- "$repo_root/Cargo.lock" | awk '{print $1}')
actual_gcc_release=$("$gcc" -dumpfullversion)
actual_binutils_release=$("$objdump" --version | sed -n '1s/.* //p')
actual_windres_release=$("$windres" --version | sed -n '1s/.* //p')
actual_brand_hash=$(sha256sum -- "$repo_root/assets/langnaux-learn.png" | awk '{print $1}')
actual_icon_hash=$(sha256sum -- "$repo_root/assets/langnaux-learn.ico" | awk '{print $1}')
actual_locale_hash=$(
    cd -- "$repo_root/naux-lang/locales"
    for locale_file in "${locale_files[@]}"; do
        sha256sum -- "$locale_file"
    done | sha256sum | awk '{print $1}'
)
target_libdir=$(rustc --print target-libdir --target "$expected_target" 2>/dev/null || true)

if [[ "$actual_rustc_release" != "$expected_rustc_release" \
    || "$actual_rustc_commit" != "$expected_rustc_commit" \
    || "$actual_cargo_release" != "$expected_cargo_release" \
    || "$actual_cargo_commit" != "$expected_cargo_commit" \
    || "$actual_host" != "$expected_host" \
    || "$actual_lock_hash" != "$expected_lock_hash" \
    || "$actual_gcc_release" != "$expected_gcc_release" \
    || "$actual_binutils_release" != "$expected_objdump_release" \
    || "$actual_windres_release" != "$expected_objdump_release" \
    || "$actual_brand_hash" != "$expected_brand_hash" \
    || "$actual_icon_hash" != "$expected_icon_hash" \
    || "$actual_locale_hash" != "$expected_locale_hash" \
    || ! -d "$target_libdir" \
    || "$expected_epoch" != "0" \
    || "$expected_timestamp_policy" != "--no-insert-timestamp" ]]; then
    echo "active Windows cross-build seed does not match BUILD-SEED.tsv" >&2
    exit 1
fi

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
if [[ "naux@$actual_package_version" != "$expected_package" ]]; then
    echo "Cargo package version differs from the Windows build seed" >&2
    exit 1
fi

mkdir -p -- "$output_parent"
staging="$output_parent/.$output_leaf.staging-$$"
manifest_body="$output_parent/.$output_leaf.manifest-$$"
if [[ -e "$staging" || -L "$staging" \
    || -e "$manifest_body" || -L "$manifest_body" ]]; then
    echo "Windows bundle staging path already exists" >&2
    exit 2
fi
cleanup() {
    rm -rf -- "$staging"
    rm -f -- "$manifest_body"
}
trap cleanup EXIT

windows_target_dir=${NAUX_WINDOWS_CARGO_TARGET_DIR:-"$repo_root/target/windows-release-build"}
if [[ -z "$windows_target_dir" || "$windows_target_dir" == "/" ]]; then
    echo "refusing unsafe Windows Cargo target directory" >&2
    exit 2
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
        -u CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS \
        -u RUSTC_WORKSPACE_WRAPPER \
        -u RUSTC_WRAPPER \
        CARGO_INCREMENTAL=0 \
        CARGO_TARGET_DIR="$windows_target_dir" \
        CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$gcc" \
        NAUX_WINDOWS_WINDRES="$windres" \
        RUSTFLAGS='-C link-arg=-Wl,--no-insert-timestamp' \
        SOURCE_DATE_EPOCH=0 \
        cargo build --locked --release -p naux \
            --bin naux \
            --bin naux-learn-setup \
            --target "$expected_target"
)

binary="$windows_target_dir/$expected_target/release/naux.exe"
setup_binary="$windows_target_dir/$expected_target/release/naux-learn-setup.exe"
if [[ ! -f "$binary" || ! -f "$setup_binary" ]]; then
    echo "Windows producer did not emit both naux.exe and naux-learn-setup.exe" >&2
    exit 1
fi
pe_offset=$(od -An -tu4 -j 60 -N 4 -- "$binary" | tr -d ' ')
timestamp_offset=$((pe_offset + 8))
pe_timestamp=$(od -An -tu4 -j "$timestamp_offset" -N 4 -- "$binary" | tr -d ' ')
pe_report=$("$objdump" -p -- "$binary")
file_format=$(printf '%s\n' "$pe_report" | sed -n 's/.*file format //p' | head -n 1)
subsystem=$(printf '%s\n' "$pe_report" | sed -n 's/^Subsystem[[:space:]]*[0-9a-fA-F]*[[:space:]]*(\([^)]*\)).*/\1/p')
dll_characteristics=$(printf '%s\n' "$pe_report" | sed -n 's/^DllCharacteristics[[:space:]]*//p' | head -n 1)
actual_needed=$(printf '%s\n' "$pe_report" | sed -n 's/^[[:space:]]*DLL Name: //p' | sort -u)
setup_pe_offset=$(od -An -tu4 -j 60 -N 4 -- "$setup_binary" | tr -d ' ')
setup_timestamp_offset=$((setup_pe_offset + 8))
setup_pe_timestamp=$(od -An -tu4 -j "$setup_timestamp_offset" -N 4 -- "$setup_binary" | tr -d ' ')
setup_pe_report=$("$objdump" -p -- "$setup_binary")
setup_file_format=$(printf '%s\n' "$setup_pe_report" | sed -n 's/.*file format //p' | head -n 1)
setup_subsystem=$(printf '%s\n' "$setup_pe_report" | sed -n 's/^Subsystem[[:space:]]*[0-9a-fA-F]*[[:space:]]*(\([^)]*\)).*/\1/p')
setup_dll_characteristics=$(printf '%s\n' "$setup_pe_report" | sed -n 's/^DllCharacteristics[[:space:]]*//p' | head -n 1)
setup_actual_needed=$(printf '%s\n' "$setup_pe_report" | sed -n 's/^[[:space:]]*DLL Name: //p' | sort -u)
expected_needed=$(awk -F '\t' '$1 == "needed" { print $2 }' "$source_dir/HOST-DEPENDENCIES.tsv" | sort -u)
if [[ "$pe_timestamp" != "0" \
    || "$setup_pe_timestamp" != "0" \
    || "$file_format" != "pei-x86-64" \
    || "$setup_file_format" != "pei-x86-64" \
    || "$subsystem" != "Windows CUI" \
    || "$setup_subsystem" != "Windows CUI" \
    || "$dll_characteristics" != "00000160" \
    || "$setup_dll_characteristics" != "00000160" \
    || "$actual_needed" != "$expected_needed" \
    || "$setup_actual_needed" != "$expected_needed" ]]; then
    echo "Windows PE boundary differs from HOST-DEPENDENCIES.tsv" >&2
    exit 1
fi

mkdir -p -- "$staging/assets" "$staging/bin" "$staging/docs" "$staging/examples" "$staging/locales"
chmod 0755 -- "$staging" "$staging/assets" "$staging/bin" "$staging/docs" "$staging/examples" "$staging/locales"
install -m 0644 -- "$source_dir/BUILD-SEED.tsv" "$staging/BUILD-SEED.tsv"
install -m 0644 -- "$source_dir/HOST-DEPENDENCIES.tsv" "$staging/HOST-DEPENDENCIES.tsv"
install -m 0644 -- "$repo_root/LICENSE" "$staging/LICENSE"
sed 's#../../../assets/langnaux-learn.png#assets/langnaux-learn.png#' \
    "$source_dir/README.md" > "$staging/README.md"
chmod 0644 -- "$staging/README.md"
install -m 0755 -- "$setup_binary" "$staging/NAUX-Learn-Setup.exe"
install -m 0644 -- "$repo_root/assets/langnaux-learn.ico" "$staging/assets/langnaux-learn.ico"
install -m 0644 -- "$repo_root/assets/langnaux-learn.png" "$staging/assets/langnaux-learn.png"
install -m 0755 -- "$binary" "$staging/bin/naux.exe"
install -m 0644 -- "$source_dir/LIMITATIONS.md" "$staging/docs/LIMITATIONS.md"
install -m 0644 -- "$repo_root/distribution/s1-learn/RELEASE_DISCLOSURE.md" "$staging/docs/RELEASE_DISCLOSURE.md"
install -m 0644 -- "$repo_root/docs/s1_learn_batch_io.md" "$staging/docs/s1_learn_batch_io.md"
install -m 0644 -- "$repo_root/docs/s1_learn_diagnostics.md" "$staging/docs/s1_learn_diagnostics.md"
install -m 0644 -- "$repo_root/docs/s1_learn_execution_envelope.md" "$staging/docs/s1_learn_execution_envelope.md"
install -m 0644 -- "$repo_root/docs/s1_learn_quick_reference_v0_1.md" "$staging/docs/s1_learn_quick_reference_v0_1.md"
install -m 0644 -- "$repo_root/distribution/s1-learn/hello.nx" "$staging/examples/hello.nx"
install -m 0644 -- "$repo_root/distribution/s1-learn/hello.out" "$staging/examples/hello.out"
for locale_file in "${locale_files[@]}"; do
    install -m 0644 -- "$repo_root/naux-lang/locales/$locale_file" "$staging/locales/$locale_file"
done

files=(
    BUILD-SEED.tsv
    HOST-DEPENDENCIES.tsv
    LICENSE
    README.md
    NAUX-Learn-Setup.exe
    assets/langnaux-learn.ico
    assets/langnaux-learn.png
    bin/naux.exe
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
modes=(0644 0644 0644 0644 0755 0644 0644 0755 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644)
{
    printf 'NAUX-S1-LEARN-BUNDLE\t1\n'
    printf 'bundle\t%s\n' "$version"
    printf 'target\twindows-x86_64-gnu\n'
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

host_verifier=${NAUX_HOST_VERIFIER:-"$repo_root/target/release/naux"}
if [[ ! -x "$host_verifier" ]]; then
    echo "set NAUX_HOST_VERIFIER to a current Linux NAUX verifier executable" >&2
    exit 1
fi
if [[ $("$host_verifier" --version) != "naux $version" ]]; then
    echo "host verifier version does not match Windows bundle" >&2
    exit 1
fi
"$host_verifier" installation verify-windows-icon \
    "$binary" "$repo_root/assets/langnaux-learn.ico" > /dev/null
"$host_verifier" installation verify-windows-icon \
    "$setup_binary" "$repo_root/assets/langnaux-learn.ico" > /dev/null
"$host_verifier" bundle verify "$staging" > /dev/null

mv -- "$staging" "$output"
trap - EXIT
printf 'bundle: %s\n' "$output"
printf 'manifest-seal: %s\n' "$seal"
