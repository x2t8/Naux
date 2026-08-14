#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C
export TZ=UTC

if [[ $# -ne 2 ]]; then
    echo "usage: scripts/verify_s1_release_windows.sh <archive.zip> <archive.zip.sha256>" >&2
    exit 2
fi

archive=$1
checksum=$2
archive_dir=$(CDPATH= cd -- "$(dirname -- "$archive")" && pwd)
archive_base=$(basename -- "$archive")
checksum_dir=$(CDPATH= cd -- "$(dirname -- "$checksum")" && pwd)
checksum_base=$(basename -- "$checksum")
if [[ ! "$archive_base" =~ ^naux-learn-([0-9]+\.[0-9]+\.[0-9]+)-windows-x86_64-gnu\.zip$ ]]; then
    echo "Windows release archive has a noncanonical name" >&2
    exit 1
fi
version=${BASH_REMATCH[1]}
root_name=${archive_base%.zip}
if [[ "$checksum_base" != "$archive_base.sha256" || "$archive_dir" != "$checksum_dir" ]]; then
    echo "Windows release checksum must be the adjacent canonical .sha256 file" >&2
    exit 1
fi
if [[ $(stat -c %s -- "$archive") -gt 20971520 ]]; then
    echo "Windows release archive exceeds the 20 MiB compressed cap" >&2
    exit 1
fi

checksum_line=$(cat -- "$checksum")
declared_hash=${checksum_line%%  *}
expected_checksum_bytes=$((64 + 2 + ${#archive_base} + 1))
if [[ $(stat -c %s -- "$checksum") -ne $expected_checksum_bytes \
    || ! "$declared_hash" =~ ^[0-9a-f]{64}$ \
    || "$checksum_line" != "$declared_hash  $archive_base" ]]; then
    echo "Windows release checksum file is noncanonical" >&2
    exit 1
fi
(
    cd -- "$archive_dir"
    sha256sum --check --strict -- "$checksum_base" > /dev/null
)

zip_command=${NAUX_WINDOWS_ZIP:-}
if [[ -z "$zip_command" ]]; then
    zip_command=$(command -v zip || true)
fi
objdump_command=${NAUX_WINDOWS_OBJDUMP:-}
if [[ -z "$objdump_command" ]]; then
    objdump_command=$(command -v objdump || true)
fi
host_verifier=${NAUX_HOST_VERIFIER:-}
if [[ -z "$host_verifier" ]]; then
    script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
    host_verifier="$repo_root/target/release/naux"
fi
for command in bsdtar cmp od sha256sum stat "$zip_command" "$objdump_command" "$host_verifier"; do
    if [[ -z "$command" ]] || ! command -v "$command" > /dev/null 2>&1; then
        echo "required Windows release verifier command is missing: $command" >&2
        exit 1
    fi
done
if ! "$zip_command" -v | grep -F "This is Zip 3.0" > /dev/null; then
    echo "Windows canonical replay requires Info-ZIP 3.0" >&2
    exit 1
fi

temp_root=$(mktemp -d "${TMPDIR:-/tmp}/naux-s1-windows-release-verify.XXXXXXXX")
cleanup() {
    rm -rf -- "$temp_root"
}
trap cleanup EXIT
expected="$temp_root/expected.txt"
actual="$temp_root/actual.txt"
verbose="$temp_root/verbose.txt"
cat > "$expected" <<EOF
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

bsdtar --list --file "$archive" > "$actual"
cmp -- "$expected" "$actual" > /dev/null
bsdtar --list --verbose --file "$archive" > "$verbose"
entry_count=0
total_bytes=0
while IFS= read -r line; do
    mode=${line%% *}
    type=${mode:0:1}
    if [[ "$type" != "-" && "$type" != "d" ]]; then
        echo "Windows release archive contains a non-file, non-directory member" >&2
        exit 1
    fi
    if [[ "$type" == "d" && "$mode" != "drwxr-xr-x" ]]; then
        echo "Windows release directory transport mode is noncanonical" >&2
        exit 1
    fi
    size=$(awk '{print $5}' <<< "$line")
    if [[ ! "$size" =~ ^[0-9]+$ ]]; then
        echo "Windows release archive has a noncanonical size listing" >&2
        exit 1
    fi
    entry_count=$((entry_count + 1))
    path=$(awk '{print $NF}' <<< "$line")
    if [[ "$path" == "$root_name/NAUX-Learn-Setup.exe" \
        || "$path" == "$root_name/bin/naux.exe" ]]; then
        if [[ "$mode" != "-rwxr-xr-x" ]]; then
            echo "Windows executable transport mode is noncanonical" >&2
            exit 1
        fi
    elif [[ "$type" == "-" && "$mode" != "-rw-r--r--" ]]; then
        echo "Windows release file transport mode is noncanonical" >&2
        exit 1
    fi
    total_bytes=$((total_bytes + size))
    if [[ $entry_count -gt 40 || $total_bytes -gt 33554432 ]]; then
        echo "Windows release archive exceeds its entry or expanded-byte cap" >&2
        exit 1
    fi
done < "$verbose"

extract="$temp_root/extract"
mkdir -m 0755 -- "$extract"
bsdtar --extract --file "$archive" --directory "$extract" --no-same-owner
bundle="$extract/$root_name"
"$host_verifier" bundle verify "$bundle" > /dev/null

binary="$bundle/bin/naux.exe"
setup_binary="$bundle/NAUX-Learn-Setup.exe"
"$host_verifier" installation verify-windows-icon \
    "$binary" "$bundle/assets/langnaux-learn.ico" > /dev/null
"$host_verifier" installation verify-windows-icon \
    "$setup_binary" "$bundle/assets/langnaux-learn.ico" > /dev/null
pe_offset=$(od -An -tu4 -j 60 -N 4 -- "$binary" | tr -d ' ')
timestamp_offset=$((pe_offset + 8))
pe_timestamp=$(od -An -tu4 -j "$timestamp_offset" -N 4 -- "$binary" | tr -d ' ')
pe_report=$("$objdump_command" -p -- "$binary")
file_format=$(printf '%s\n' "$pe_report" | sed -n 's/.*file format //p' | head -n 1)
subsystem=$(printf '%s\n' "$pe_report" | sed -n 's/^Subsystem[[:space:]]*[0-9a-fA-F]*[[:space:]]*(\([^)]*\)).*/\1/p')
dll_characteristics=$(printf '%s\n' "$pe_report" | sed -n 's/^DllCharacteristics[[:space:]]*//p' | head -n 1)
actual_needed=$(printf '%s\n' "$pe_report" | sed -n 's/^[[:space:]]*DLL Name: //p' | sort -u)
expected_needed=$(awk -F '\t' '$1 == "needed" { print $2 }' "$bundle/HOST-DEPENDENCIES.tsv" | sort -u)
setup_pe_offset=$(od -An -tu4 -j 60 -N 4 -- "$setup_binary" | tr -d ' ')
setup_timestamp_offset=$((setup_pe_offset + 8))
setup_pe_timestamp=$(od -An -tu4 -j "$setup_timestamp_offset" -N 4 -- "$setup_binary" | tr -d ' ')
setup_pe_report=$("$objdump_command" -p -- "$setup_binary")
setup_file_format=$(printf '%s\n' "$setup_pe_report" | sed -n 's/.*file format //p' | head -n 1)
setup_subsystem=$(printf '%s\n' "$setup_pe_report" | sed -n 's/^Subsystem[[:space:]]*[0-9a-fA-F]*[[:space:]]*(\([^)]*\)).*/\1/p')
setup_dll_characteristics=$(printf '%s\n' "$setup_pe_report" | sed -n 's/^DllCharacteristics[[:space:]]*//p' | head -n 1)
setup_actual_needed=$(printf '%s\n' "$setup_pe_report" | sed -n 's/^[[:space:]]*DLL Name: //p' | sort -u)
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
    echo "Windows release PE boundary differs from the admitted host inventory" >&2
    exit 1
fi

find "$bundle" -exec touch -h -d '@315532800' -- {} +
repacked="$temp_root/repacked.zip"
(
    cd -- "$extract"
    "$zip_command" -q -X -9 "$repacked" -@ < "$expected"
)
if ! cmp -- "$archive" "$repacked" > /dev/null; then
    echo "Windows release archive is not the canonical deterministic ZIP encoding" >&2
    exit 1
fi

printf 'windows-release-archive: verified\n'
printf 'version: %s\n' "$version"
printf 'entries: %s\n' "$entry_count"
printf 'expanded-bytes: %s\n' "$total_bytes"
printf 'runtime-gate: real Windows 10/11 carrier pending\n'
