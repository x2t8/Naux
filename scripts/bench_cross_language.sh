#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/target/perf/cross_language}"
BUILD_DIR="${BUILD_DIR:-$OUT_DIR/build}"
CPU_CORE="${CPU_CORE:-0}"
ITERS="${ITERS:-50}"
WARMUP_MS="${WARMUP_MS:-100}"
REPS="${REPS:-50}"
N="${N:-100000}"
ENGINE="${ENGINE:-jit}"

NAUX_RUSTFLAGS="${NAUX_RUSTFLAGS:--C target-cpu=native}"
RUST_BASELINE_RUSTFLAGS="${RUST_BASELINE_RUSTFLAGS:--C target-cpu=native}"
C_FLAGS="${C_FLAGS:--O3 -march=native}"
CPP_FLAGS="${CPP_FLAGS:--O3 -march=native -std=c++20}"
GO_BUILD_FLAGS="${GO_BUILD_FLAGS:--trimpath}"
ZIG_FLAGS="${ZIG_FLAGS:--O ReleaseFast -mcpu native}"

EXPECT_GOVERNOR="${EXPECT_GOVERNOR:-performance}"
EXPECT_INTEL_NO_TURBO="${EXPECT_INTEL_NO_TURBO:-1}"
ENFORCE_CLAIM_ENV="${ENFORCE_CLAIM_ENV:-0}"
REQUIRE_NAUX_BEAT_C="${REQUIRE_NAUX_BEAT_C:-0}"
REQUIRE_NAUX_BEAT_CPP="${REQUIRE_NAUX_BEAT_CPP:-0}"
MIN_CLAIM_ITERS="${MIN_CLAIM_ITERS:-30}"
MIN_CLAIM_WARMUP_MS="${MIN_CLAIM_WARMUP_MS:-100}"
MAX_CLAIM_CV_PCT="${MAX_CLAIM_CV_PCT:-5}"

BENCH_NAMES=("sum_dense" "list_update" "dot_product" "branch_mix")
NAUX_FILES=(
    "naux-lang/examples/bench_sum_dense.nx"
    "naux-lang/examples/bench_list_update.nx"
    "naux-lang/examples/bench_dot_product.nx"
    "naux-lang/examples/bench_branch_mix.nx"
)
C_SRCS=(
    "benchmarks/c/bench_sum_dense.c"
    "benchmarks/c/bench_list_update.c"
    "benchmarks/c/bench_dot_product.c"
    "benchmarks/c/bench_branch_mix.c"
)
GO_SRCS=(
    "benchmarks/go/bench_sum_dense.go"
    "benchmarks/go/bench_list_update.go"
    "benchmarks/go/bench_dot_product.go"
    "benchmarks/go/bench_branch_mix.go"
)
RUST_BINS=("bench_sum_dense" "bench_list_update" "bench_dot_product" "bench_branch_mix")

for cmd in cargo cc c++ go perl python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[cross] missing required command: $cmd" >&2
        exit 1
    fi
done

for numeric_value in "$CPU_CORE" "$ITERS" "$WARMUP_MS" "$REPS" "$N" "$MIN_CLAIM_ITERS" "$MIN_CLAIM_WARMUP_MS"; do
    if [[ ! "$numeric_value" =~ ^[0-9]+$ ]]; then
        echo "[cross] expected non-negative integer, got: $numeric_value" >&2
        exit 2
    fi
done
if (( ITERS == 0 || REPS == 0 || N == 0 || MIN_CLAIM_ITERS == 0 )); then
    echo "[cross] ITERS, REPS, N, and MIN_CLAIM_ITERS must be greater than zero" >&2
    exit 2
fi
if ! awk -v value="$MAX_CLAIM_CV_PCT" 'BEGIN { exit !(value ~ /^[0-9]+([.][0-9]+)?$/) }'; then
    echo "[cross] MAX_CLAIM_CV_PCT must be a non-negative number" >&2
    exit 2
fi

mkdir -p "$OUT_DIR" "$BUILD_DIR/c" "$BUILD_DIR/cpp" "$BUILD_DIR/go"

TMP_DIR="$(mktemp -d "$OUT_DIR/naux-inputs.XXXXXX")"
cleanup() {
    case "$TMP_DIR" in
        "$OUT_DIR"/naux-inputs.*) rm -rf -- "$TMP_DIR" ;;
    esac
}
trap cleanup EXIT

PIN=()
PIN_STATUS="unavailable"
if command -v taskset >/dev/null 2>&1 && taskset -c "$CPU_CORE" true >/dev/null 2>&1; then
    PIN=(taskset -c "$CPU_CORE")
    PIN_STATUS="pinned"
fi

run_pinned() {
    "${PIN[@]}" "$@"
}

parse_metric() {
    local key="$1"
    local data="$2"
    printf '%s\n' "$data" | sed -n "s/.*${key}=\\([0-9][0-9]*\\).*/\\1/p" | head -n1
}

parse_checksum() {
    local data="$1"
    printf '%s\n' "$data" | sed -n 's/.*checksum=\([-+0-9.eE][0-9.eE+-]*\).*/\1/p' | head -n1
}

parse_float_metric() {
    local key="$1"
    local data="$2"
    printf '%s\n' "$data" | sed -n "s/.*${key}=\\([0-9][0-9.]*\\).*/\\1/p" | head -n1
}

ratio() {
    local baseline_ns="$1"
    local naux_ns="$2"
    awk -v baseline="$baseline_ns" -v naux="$naux_ns" \
        'BEGIN { if (naux == 0) print "0.000000"; else printf "%.6f", baseline / naux }'
}

checksum_matches() {
    local expected="$1"
    local actual="$2"
    awk -v expected="$expected" -v actual="$actual" '
        BEGIN {
            diff = expected - actual
            if (diff < 0) diff = -diff
            scale = expected
            if (scale < 0) scale = -scale
            if (scale < 1) scale = 1
            exit !(diff <= (scale * 1e-12 + 1e-6))
        }
    '
}

read -r -a c_flag_args <<< "$C_FLAGS"
read -r -a cpp_flag_args <<< "$CPP_FLAGS"
read -r -a go_flag_args <<< "$GO_BUILD_FLAGS"
read -r -a zig_flag_args <<< "$ZIG_FLAGS"

zig_available="false"
zig_version="missing"
if command -v zig >/dev/null 2>&1; then
    zig_available="true"
    zig_version="$(zig version 2>&1 | head -n1)"
fi

echo "[cross] build Naux release: RUSTFLAGS=\"$NAUX_RUSTFLAGS\""
(
    cd "$ROOT_DIR"
    RUSTFLAGS="$NAUX_RUSTFLAGS" cargo build -p naux --release
)

if [[ "$zig_available" == "true" ]]; then
    echo "[cross] build Zig baselines in $BUILD_DIR/zig"
    mkdir -p "$BUILD_DIR/zig"
    zig build-exe "${zig_flag_args[@]}" \
        -femit-bin="$BUILD_DIR/zig/bench_baselines" \
        "$ROOT_DIR/benchmarks/zig/bench_baselines.zig"
fi

echo "[cross] build C baselines in $BUILD_DIR/c"
for i in "${!BENCH_NAMES[@]}"; do
    cc "${c_flag_args[@]}" \
        -o "$BUILD_DIR/c/${BENCH_NAMES[$i]}" \
        "$ROOT_DIR/${C_SRCS[$i]}" \
        -lm
done

echo "[cross] build C++ baselines in $BUILD_DIR/cpp"
c++ "${cpp_flag_args[@]}" \
    -o "$BUILD_DIR/cpp/bench_baselines" \
    "$ROOT_DIR/benchmarks/cpp/bench_baselines.cpp"

echo "[cross] build Go baselines in $BUILD_DIR/go"
for i in "${!BENCH_NAMES[@]}"; do
    go build "${go_flag_args[@]}" \
        -o "$BUILD_DIR/go/${BENCH_NAMES[$i]}" \
        "$ROOT_DIR/${GO_SRCS[$i]}"
done

echo "[cross] build Rust baselines in $BUILD_DIR/rust-target"
(
    cd "$ROOT_DIR"
    CARGO_TARGET_DIR="$BUILD_DIR/rust-target" \
        RUSTFLAGS="$RUST_BASELINE_RUSTFLAGS" \
        cargo build --manifest-path benchmarks/rust/Cargo.toml --release
)

for i in "${!BENCH_NAMES[@]}"; do
    source_path="$ROOT_DIR/${NAUX_FILES[$i]}"
    runtime_path="$TMP_DIR/${BENCH_NAMES[$i]}.nx"
    validation_path="$TMP_DIR/${BENCH_NAMES[$i]}.validation.nx"
    perl -0pe \
        "s/\\\$n = [0-9]+/\\\$n = ${N}/; s/\\\$reps = [0-9]+/\\\$reps = ${REPS}/" \
        "$source_path" > "$runtime_path"
    perl -0pe \
        's/\n    \^ \$total/\n    !say \$total\n    ^ \$total/' \
        "$runtime_path" > "$validation_path"
done

TSV="$OUT_DIR/cross_language.tsv"
JSON="$OUT_DIR/cross_language.json"
MD="$OUT_DIR/cross_language.md"
: > "$TSV"

FAILED=0
CLAIM_BLOCKERS=()
NAUX_EXECUTION_ROWS=()

for i in "${!BENCH_NAMES[@]}"; do
    name="${BENCH_NAMES[$i]}"
    naux_file="$TMP_DIR/${name}.nx"
    validation_file="$TMP_DIR/${name}.validation.nx"

    echo "[cross] run $name"
    naux_out="$(run_pinned "$ROOT_DIR/target/release/naux" \
        dev benchrt "$naux_file" \
        --engine="$ENGINE" \
        --iters="$ITERS" \
        --warmup-ms="$WARMUP_MS")"
    validation_out="$(run_pinned "$ROOT_DIR/target/release/naux" \
        dev run "$validation_file" \
        --engine="$ENGINE" \
        --mode=cli)"
    c_out="$(run_pinned "$BUILD_DIR/c/$name" "$N" "$ITERS" "$WARMUP_MS" "$REPS")"
    cpp_out="$(run_pinned "$BUILD_DIR/cpp/bench_baselines" "$name" "$N" "$ITERS" "$WARMUP_MS" "$REPS")"
    go_out="$(run_pinned "$BUILD_DIR/go/$name" "$N" "$ITERS" "$WARMUP_MS" "$REPS")"
    rust_out="$(run_pinned "$BUILD_DIR/rust-target/release/${RUST_BINS[$i]}" "$N" "$ITERS" "$WARMUP_MS" "$REPS")"
    zig_out=""
    if [[ "$zig_available" == "true" ]]; then
        zig_out="$(run_pinned "$BUILD_DIR/zig/bench_baselines" "$name" "$N" "$ITERS" "$WARMUP_MS" "$REPS" 2>&1)"
    fi

    printf '%s\n' "$naux_out" > "$OUT_DIR/${name}.naux.log"
    printf '%s\n' "$validation_out" > "$OUT_DIR/${name}.naux.validation.log"
    printf '%s\n' "$c_out" > "$OUT_DIR/${name}.c.log"
    printf '%s\n' "$cpp_out" > "$OUT_DIR/${name}.cpp.log"
    printf '%s\n' "$go_out" > "$OUT_DIR/${name}.go.log"
    printf '%s\n' "$rust_out" > "$OUT_DIR/${name}.rust.log"
    if [[ "$zig_available" == "true" ]]; then
        printf '%s\n' "$zig_out" > "$OUT_DIR/${name}.zig.log"
    fi

    naux_median="$(parse_metric median "$naux_out")"
    naux_p95="$(parse_metric p95 "$naux_out")"
    naux_cv_pct="$(parse_float_metric cv_pct "$naux_out")"
    naux_checksum="$(printf '%s\n' "$validation_out" | sed -n 's/^> //p' | head -n1)"
    naux_fallback="false"
    if [[ "$naux_out" == *'[WARN] JIT fallback -> VM occurred.'* ]]; then
        naux_fallback="true"
    fi
    naux_trace_count="$(
        printf '%s\n' "$naux_out" \
            | sed -n 's/^\[TRACE\] count=\([0-9][0-9]*\).*/\1/p' \
            | head -n1
    )"
    naux_deopts="$(
        printf '%s\n' "$naux_out" \
            | sed -n 's/^\[TRACE\].* deopt=\([0-9][0-9]*\) .*/\1/p' \
            | head -n1
    )"
    naux_internal_side_exits="$(
        printf '%s\n' "$naux_out" \
            | sed -n 's/^\[TRACE\].* internal_side_exits=\([0-9][0-9]*\) .*/\1/p' \
            | head -n1
    )"
    naux_static_branches="$(
        printf '%s\n' "$naux_out" \
            | sed -n 's/^\[TRACE\].* branches(static\/runtime\/taken\/not)=\([0-9][0-9]*\)\/.*/\1/p' \
            | head -n1
    )"
    naux_trace_count="${naux_trace_count:-0}"
    naux_deopts="${naux_deopts:-0}"
    naux_internal_side_exits="${naux_internal_side_exits:-0}"
    naux_static_branches="${naux_static_branches:-0}"

    if [[ -z "$naux_median" || -z "$naux_p95" || -z "$naux_cv_pct" || -z "$naux_checksum" ]]; then
        echo "[cross] failed to parse Naux output for $name" >&2
        FAILED=1
        continue
    fi
    if [[ "$ENGINE" == "jit" ]]; then
        if [[ "$naux_fallback" == "true" ]]; then
            echo "[cross] JIT fallback is forbidden for $name" >&2
            CLAIM_BLOCKERS+=("JIT fallback occurred for $name/naux")
            FAILED=1
        fi
        if (( naux_trace_count == 0 )); then
            echo "[cross] JIT trace coverage is missing for $name" >&2
            CLAIM_BLOCKERS+=("JIT trace coverage is missing for $name/naux")
            FAILED=1
        fi
    fi
    if [[ "$name" == "branch_mix" && "$ENGINE" == "jit" ]]; then
        if (( naux_internal_side_exits != 0 )); then
            echo "[cross] branch_mix left native control flow" >&2
            CLAIM_BLOCKERS+=("branch_mix has internal side exits")
            FAILED=1
        fi
        if (( naux_static_branches < 3 )); then
            echo "[cross] branch_mix native branch coverage is missing" >&2
            CLAIM_BLOCKERS+=("branch_mix native branch coverage is missing")
            FAILED=1
        fi
    fi
    NAUX_EXECUTION_ROWS+=(
        "$name,$naux_fallback,$naux_trace_count,$naux_deopts,$naux_internal_side_exits,$naux_static_branches"
    )
    if ! awk -v cv="$naux_cv_pct" -v limit="$MAX_CLAIM_CV_PCT" \
        'BEGIN { exit !(cv <= limit) }'; then
        CLAIM_BLOCKERS+=("cv_pct=$naux_cv_pct exceeds $MAX_CLAIM_CV_PCT for $name/naux")
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$name" "naux" "$naux_median" "$naux_p95" "$naux_cv_pct" "$naux_checksum" "1" "1.000000" >> "$TSV"

    implementations=("c" "cpp" "go" "rust")
    outputs=("$c_out" "$cpp_out" "$go_out" "$rust_out")
    if [[ "$zig_available" == "true" ]]; then
        implementations+=("zig")
        outputs+=("$zig_out")
    fi
    for impl_index in "${!implementations[@]}"; do
        impl="${implementations[$impl_index]}"
        output="${outputs[$impl_index]}"
        median="$(parse_metric median "$output")"
        p95="$(parse_metric p95 "$output")"
        cv_pct="$(parse_float_metric cv_pct "$output")"
        checksum="$(parse_checksum "$output")"
        checksum_ok="0"

        if [[ -z "$median" || -z "$p95" || -z "$cv_pct" || -z "$checksum" ]]; then
            echo "[cross] failed to parse $impl output for $name" >&2
            FAILED=1
            continue
        fi
        if ! awk -v cv="$cv_pct" -v limit="$MAX_CLAIM_CV_PCT" \
            'BEGIN { exit !(cv <= limit) }'; then
            CLAIM_BLOCKERS+=("cv_pct=$cv_pct exceeds $MAX_CLAIM_CV_PCT for $name/$impl")
        fi
        if checksum_matches "$naux_checksum" "$checksum"; then
            checksum_ok="1"
        else
            echo "[cross] checksum mismatch: benchmark=$name impl=$impl naux=$naux_checksum actual=$checksum" >&2
            CLAIM_BLOCKERS+=("checksum mismatch for $name/$impl")
            FAILED=1
        fi

        relative="$(ratio "$median" "$naux_median")"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$name" "$impl" "$median" "$p95" "$cv_pct" "$checksum" "$checksum_ok" "$relative" >> "$TSV"

        if [[ "$impl" == "c" && "$REQUIRE_NAUX_BEAT_C" == "1" && "$median" -le "$naux_median" ]]; then
            echo "[cross] gate failed: Naux does not beat C on $name" >&2
            FAILED=1
        fi
        if [[ "$impl" == "cpp" && "$REQUIRE_NAUX_BEAT_CPP" == "1" && "$median" -le "$naux_median" ]]; then
            echo "[cross] gate failed: Naux does not beat C++ on $name" >&2
            FAILED=1
        fi
    done
done

governor_path="/sys/devices/system/cpu/cpu${CPU_CORE}/cpufreq/scaling_governor"
intel_turbo_path="/sys/devices/system/cpu/intel_pstate/no_turbo"
governor="unknown"
intel_no_turbo="unknown"
[[ -r "$governor_path" ]] && governor="$(<"$governor_path")"
[[ -r "$intel_turbo_path" ]] && intel_no_turbo="$(<"$intel_turbo_path")"

if (( ITERS < MIN_CLAIM_ITERS )); then
    CLAIM_BLOCKERS+=("iters=$ITERS, minimum claim sample count=$MIN_CLAIM_ITERS")
fi
if (( WARMUP_MS < MIN_CLAIM_WARMUP_MS )); then
    CLAIM_BLOCKERS+=("warmup_ms=$WARMUP_MS, minimum claim warmup=$MIN_CLAIM_WARMUP_MS")
fi
if [[ "$PIN_STATUS" != "pinned" ]]; then
    CLAIM_BLOCKERS+=("CPU pinning unavailable for core $CPU_CORE")
fi
if [[ -n "$EXPECT_GOVERNOR" && "$governor" != "$EXPECT_GOVERNOR" ]]; then
    CLAIM_BLOCKERS+=("governor=$governor, expected=$EXPECT_GOVERNOR")
fi
if [[ -n "$EXPECT_INTEL_NO_TURBO" && "$intel_no_turbo" != "$EXPECT_INTEL_NO_TURBO" ]]; then
    CLAIM_BLOCKERS+=("intel_no_turbo=$intel_no_turbo, expected=$EXPECT_INTEL_NO_TURBO")
fi

git_sha="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || printf unknown)"
git_dirty="false"
if [[ -n "$(git -C "$ROOT_DIR" status --porcelain 2>/dev/null)" ]]; then
    git_dirty="true"
    CLAIM_BLOCKERS+=("worktree is dirty")
fi

if [[ "$zig_available" != "true" ]]; then
    CLAIM_BLOCKERS+=("Zig source is ready but the Zig toolchain is unavailable")
fi

timestamp_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cpu_model="unknown"
if [[ -r /proc/cpuinfo ]]; then
    cpu_model="$(awk -F: '/model name/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }' /proc/cpuinfo)"
elif command -v sysctl >/dev/null 2>&1; then
    cpu_model="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || printf unknown)"
fi
logical_core_count="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf unknown)"
physical_core_count="unknown"
if command -v lscpu >/dev/null 2>&1; then
    physical_core_count="$(
        lscpu -p=CORE,SOCKET 2>/dev/null \
            | awk -F, '!/^#/ { seen[$1 FS $2]=1 } END { print length(seen) }'
    )"
fi
memory_bytes="unknown"
if [[ -r /proc/meminfo ]]; then
    memory_bytes="$(awk '/MemTotal:/ { printf "%.0f", $2 * 1024; exit }' /proc/meminfo)"
elif command -v sysctl >/dev/null 2>&1; then
    memory_bytes="$(sysctl -n hw.memsize 2>/dev/null || printf unknown)"
fi
target_triple="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p' | head -n1)"
target_features="$(
    rustc --print cfg -C target-cpu=native 2>/dev/null \
        | sed -n 's/^target_feature=\"\\(.*\\)\"$/\\1/p' \
        | paste -sd, -
)"
reproduction_command="CPU_CORE=$CPU_CORE N=$N REPS=$REPS ITERS=$ITERS WARMUP_MS=$WARMUP_MS ENGINE=$ENGINE ENFORCE_CLAIM_ENV=1 ./scripts/bench_cross_language.sh"

if [[ "$git_sha" == "unknown" ]]; then
    CLAIM_BLOCKERS+=("Git SHA is unavailable")
fi
for fingerprint in \
    "cpu_model=$cpu_model" \
    "physical_core_count=$physical_core_count" \
    "logical_core_count=$logical_core_count" \
    "memory_bytes=$memory_bytes" \
    "target_triple=$target_triple"; do
    fingerprint_value="${fingerprint#*=}"
    if [[ -z "$fingerprint_value" || "$fingerprint_value" == "unknown" || "$fingerprint_value" == "unavailable" || "$fingerprint_value" == "0" ]]; then
        CLAIM_BLOCKERS+=("hardware fingerprint missing: ${fingerprint%%=*}")
    fi
done

claim_eligible="true"
if [[ "${#CLAIM_BLOCKERS[@]}" -gt 0 || "$FAILED" -ne 0 ]]; then
    claim_eligible="false"
fi

blockers_joined=""
if [[ "${#CLAIM_BLOCKERS[@]}" -gt 0 ]]; then
    blockers_joined="$(IFS='|'; printf '%s' "${CLAIM_BLOCKERS[*]}")"
fi

export CROSS_ROOT_DIR="$ROOT_DIR"
export CROSS_ENGINE="$ENGINE"
export CROSS_N="$N"
export CROSS_ITERS="$ITERS"
export CROSS_WARMUP_MS="$WARMUP_MS"
export CROSS_REPS="$REPS"
export CROSS_CPU_CORE="$CPU_CORE"
export CROSS_PIN_STATUS="$PIN_STATUS"
export CROSS_GOVERNOR="$governor"
export CROSS_INTEL_NO_TURBO="$intel_no_turbo"
export CROSS_GIT_SHA="$git_sha"
export CROSS_GIT_DIRTY="$git_dirty"
export CROSS_CLAIM_ELIGIBLE="$claim_eligible"
export CROSS_CLAIM_BLOCKERS="$blockers_joined"
export CROSS_ZIG_AVAILABLE="$zig_available"
export CROSS_ZIG_VERSION="$zig_version"
export CROSS_NAUX_FLAGS="$NAUX_RUSTFLAGS"
export CROSS_RUST_FLAGS="$RUST_BASELINE_RUSTFLAGS"
export CROSS_C_FLAGS="$C_FLAGS -lm"
export CROSS_CPP_FLAGS="$CPP_FLAGS"
export CROSS_GO_FLAGS="$GO_BUILD_FLAGS"
export CROSS_ZIG_FLAGS="$ZIG_FLAGS"
export CROSS_TIMESTAMP_UTC="$timestamp_utc"
export CROSS_CPU_MODEL="$cpu_model"
export CROSS_LOGICAL_CORE_COUNT="$logical_core_count"
export CROSS_PHYSICAL_CORE_COUNT="$physical_core_count"
export CROSS_MEMORY_BYTES="$memory_bytes"
export CROSS_TARGET_TRIPLE="$target_triple"
export CROSS_TARGET_FEATURES="$target_features"
export CROSS_REPRODUCTION_COMMAND="$reproduction_command"
export CROSS_MIN_CLAIM_ITERS="$MIN_CLAIM_ITERS"
export CROSS_MIN_CLAIM_WARMUP_MS="$MIN_CLAIM_WARMUP_MS"
export CROSS_MAX_CLAIM_CV_PCT="$MAX_CLAIM_CV_PCT"
export CROSS_REQUIRE_NAUX_BEAT_C="$REQUIRE_NAUX_BEAT_C"
export CROSS_REQUIRE_NAUX_BEAT_CPP="$REQUIRE_NAUX_BEAT_CPP"
export CROSS_BENCHMARK_COUNT="${#BENCH_NAMES[@]}"
export CROSS_NAUX_EXECUTION="$(IFS=';'; printf '%s' "${NAUX_EXECUTION_ROWS[*]}")"
export CROSS_RUSTC_VERSION="$(rustc --version 2>&1 | head -n1)"
export CROSS_CC_VERSION="$(cc --version 2>&1 | head -n1)"
export CROSS_CPP_VERSION="$(c++ --version 2>&1 | head -n1)"
export CROSS_GO_VERSION="$(go version 2>&1 | head -n1)"

PYTHONDONTWRITEBYTECODE=1 python3 - "$TSV" "$JSON" "$MD" <<'PY'
import json
import hashlib
import math
import os
import platform
import sys
from pathlib import Path

tsv_path = Path(sys.argv[1])
json_path = Path(sys.argv[2])
md_path = Path(sys.argv[3])

rows = []
for line in tsv_path.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    (
        benchmark,
        implementation,
        median,
        p95,
        cv_pct,
        checksum,
        checksum_ok,
        relative,
    ) = line.split("\t")
    rows.append(
        {
            "benchmark": benchmark,
            "implementation": implementation,
            "median_ns": int(median),
            "p95_ns": int(p95),
            "cv_pct": float(cv_pct),
            "checksum": float(checksum),
            "checksum_match": checksum_ok == "1",
            "baseline_over_naux": float(relative),
            "claim_stable": float(cv_pct)
            <= float(os.environ["CROSS_MAX_CLAIM_CV_PCT"]),
        }
    )

def geomean(values):
    positive = [value for value in values if value > 0]
    if not positive:
        return 0.0
    return math.exp(sum(math.log(value) for value in positive) / len(positive))

implementations = sorted({row["implementation"] for row in rows})
geomeans = {
    implementation: geomean(
        [
            row["baseline_over_naux"]
            for row in rows
            if row["implementation"] == implementation
        ]
    )
    for implementation in implementations
}
blockers = [
    blocker
    for blocker in os.environ.get("CROSS_CLAIM_BLOCKERS", "").split("|")
    if blocker
]
naux_execution = {}
for encoded in os.environ["CROSS_NAUX_EXECUTION"].split(";"):
    if not encoded:
        continue
    (
        benchmark,
        fallback,
        trace_count,
        deopts,
        internal_side_exits,
        static_branches,
    ) = encoded.split(",")
    naux_execution[benchmark] = {
        "requested_engine": os.environ["CROSS_ENGINE"],
        "fallback": fallback == "true",
        "trace_count": int(trace_count),
        "deopts": int(deopts),
        "internal_side_exits": int(internal_side_exits),
        "static_branches": int(static_branches),
    }
naux_execution_ok = (
    len(naux_execution) == int(os.environ["CROSS_BENCHMARK_COUNT"])
    and (
        os.environ["CROSS_ENGINE"] != "jit"
        or (
            all(
                not execution["fallback"] and execution["trace_count"] > 0
                for execution in naux_execution.values()
            )
            and naux_execution.get("branch_mix", {}).get("internal_side_exits") == 0
            and naux_execution.get("branch_mix", {}).get("static_branches", 0) >= 3
        )
    )
)
evidence_paths = [tsv_path, *sorted(tsv_path.parent.glob("*.log"))]
evidence_sha256 = {
    path.name: hashlib.sha256(path.read_bytes()).hexdigest()
    for path in evidence_paths
}

payload = {
    "schema_version": 2,
    "generated_at_utc": os.environ["CROSS_TIMESTAMP_UTC"],
    "status": "pass"
    if len(rows)
    == int(os.environ["CROSS_BENCHMARK_COUNT"])
    * (6 if os.environ["CROSS_ZIG_AVAILABLE"] == "true" else 5)
    and all(row["checksum_match"] for row in rows)
    and naux_execution_ok
    else "fail",
    "claim": {
        "eligible": os.environ["CROSS_CLAIM_ELIGIBLE"] == "true",
        "blockers": blockers,
        "policy": "Do not publish competitive claims unless eligible=true.",
        "kind": "competitive"
        if os.environ["CROSS_REQUIRE_NAUX_BEAT_C"] == "1"
        or os.environ["CROSS_REQUIRE_NAUX_BEAT_CPP"] == "1"
        else "baseline-observation",
        "thresholds": {
            "minimum_samples_per_implementation": int(
                os.environ["CROSS_MIN_CLAIM_ITERS"]
            ),
            "minimum_warmup_ms": int(os.environ["CROSS_MIN_CLAIM_WARMUP_MS"]),
            "maximum_cv_pct": float(os.environ["CROSS_MAX_CLAIM_CV_PCT"]),
            "require_naux_beat_c": os.environ["CROSS_REQUIRE_NAUX_BEAT_C"] == "1",
            "require_naux_beat_cpp": os.environ["CROSS_REQUIRE_NAUX_BEAT_CPP"]
            == "1",
        },
    },
    "workload": {
        "engine": os.environ["CROSS_ENGINE"],
        "n": int(os.environ["CROSS_N"]),
        "iters": int(os.environ["CROSS_ITERS"]),
        "warmup_ms": int(os.environ["CROSS_WARMUP_MS"]),
        "reps": int(os.environ["CROSS_REPS"]),
        "sample_count_per_implementation": int(os.environ["CROSS_ITERS"]),
        "statistics": ["median_ns", "p95_ns", "cv_pct"],
        "cv_definition": "population standard deviation / arithmetic mean * 100",
        "outlier_policy": (
            "no statistical outlier trimming; Naux excludes observed JIT "
            "transition/cooldown samples and records counts in its workload log"
        ),
        "timed_region": (
            "input allocation plus initialization plus kernel execution; "
            "explicit reclamation is included where the implementation exposes it"
        ),
        "definitions": {
            "sum_dense": "initialize a dense numeric list and sum it for reps passes",
            "list_update": "initialize a dense numeric list, sum and increment each element for reps passes",
            "dot_product": "initialize a dense numeric list and sum value*value for reps passes",
            "branch_mix": "initialize a dense numeric list and add or subtract each value using a branch-driven deterministic state recurrence for reps passes",
        },
    },
    "environment": {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_model": os.environ["CROSS_CPU_MODEL"],
        "physical_core_count": os.environ["CROSS_PHYSICAL_CORE_COUNT"],
        "logical_core_count": os.environ["CROSS_LOGICAL_CORE_COUNT"],
        "memory_bytes": os.environ["CROSS_MEMORY_BYTES"],
        "cpu_core": int(os.environ["CROSS_CPU_CORE"]),
        "pin_status": os.environ["CROSS_PIN_STATUS"],
        "governor": os.environ["CROSS_GOVERNOR"],
        "intel_no_turbo": os.environ["CROSS_INTEL_NO_TURBO"],
        "target_triple": os.environ["CROSS_TARGET_TRIPLE"],
        "target_features": [
            feature
            for feature in os.environ["CROSS_TARGET_FEATURES"].split(",")
            if feature
        ],
        "git_sha": os.environ["CROSS_GIT_SHA"],
        "git_dirty": os.environ["CROSS_GIT_DIRTY"] == "true",
    },
    "reproduction": {
        "command": os.environ["CROSS_REPRODUCTION_COMMAND"],
        "working_directory": ".",
    },
    "evidence_sha256": evidence_sha256,
    "toolchains": {
        "rustc": os.environ["CROSS_RUSTC_VERSION"],
        "cc": os.environ["CROSS_CC_VERSION"],
        "cpp": os.environ["CROSS_CPP_VERSION"],
        "go": os.environ["CROSS_GO_VERSION"],
        "zig": os.environ["CROSS_ZIG_VERSION"],
    },
    "coverage": {
        "naux": "measured",
        "c": "measured",
        "cpp": "measured",
        "go": "measured",
        "rust": "measured",
        "zig": "measured"
        if os.environ["CROSS_ZIG_AVAILABLE"] == "true"
        else "source-ready/toolchain-missing",
    },
    "build_flags": {
        "naux": os.environ["CROSS_NAUX_FLAGS"],
        "rust": os.environ["CROSS_RUST_FLAGS"],
        "c": os.environ["CROSS_C_FLAGS"],
        "cpp": os.environ["CROSS_CPP_FLAGS"],
        "go": os.environ["CROSS_GO_FLAGS"],
        "zig": os.environ["CROSS_ZIG_FLAGS"],
    },
    "build_profiles": {
        "naux": "cargo release",
        "c": "optimized native",
        "cpp": "optimized native C++20",
        "go": "default optimized build",
        "rust": "cargo release",
        "zig": "ReleaseFast",
    },
    "rows": rows,
    "naux_execution": naux_execution,
    "summary": {"geomean_baseline_over_naux": geomeans},
}

json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

lines = [
    "# Cross-Language Runtime Baseline",
    "",
    f"- status: `{payload['status']}`",
    f"- claim eligible: `{'yes' if payload['claim']['eligible'] else 'no'}`",
    f"- workload: `n={payload['workload']['n']}, reps={payload['workload']['reps']}, "
    f"iters={payload['workload']['iters']}, warmup_ms={payload['workload']['warmup_ms']}`",
    f"- statistics: `median, p95, CV`; claim CV limit: "
    f"`{payload['claim']['thresholds']['maximum_cv_pct']:.2f}%`",
    f"- engine: `{payload['workload']['engine']}`",
    f"- CPU: core `{payload['environment']['cpu_core']}`, "
    f"pin=`{payload['environment']['pin_status']}`, "
    f"governor=`{payload['environment']['governor']}`, "
    f"intel_no_turbo=`{payload['environment']['intel_no_turbo']}`",
    f"- git: `{payload['environment']['git_sha']}` "
    f"({'dirty' if payload['environment']['git_dirty'] else 'clean'})",
]
if blockers:
    lines.extend(["", "## Claim blockers", ""])
    lines.extend(f"- {blocker}" for blocker in blockers)

lines.extend(
    [
        "",
        "## Naux execution certificate",
        "",
        "| benchmark | requested engine | fallback | traces | deopts | internal side exits | static branches |",
        "|---|---|:---:|---:|---:|---:|---:|",
    ]
)
for benchmark, execution in sorted(naux_execution.items()):
    lines.append(
        f"| {benchmark} | {execution['requested_engine']} | "
        f"{'YES' if execution['fallback'] else 'no'} | "
        f"{execution['trace_count']} | {execution['deopts']} | "
        f"{execution['internal_side_exits']} | {execution['static_branches']} |"
    )

lines.extend(
    [
        "",
        "## Results",
        "",
        "| benchmark | implementation | median ns/op | p95 ns/op | CV % | stable | checksum | match | baseline/Naux |",
        "|---|---|---:|---:|---:|:---:|---:|:---:|---:|",
    ]
)
for row in rows:
    lines.append(
        f"| {row['benchmark']} | {row['implementation']} | {row['median_ns']} | "
        f"{row['p95_ns']} | {row['cv_pct']:.4f} | "
        f"{'yes' if row['claim_stable'] else 'NO'} | {row['checksum']:.17g} | "
        f"{'yes' if row['checksum_match'] else 'NO'} | "
        f"{row['baseline_over_naux']:.3f} |"
    )

lines.extend(["", "## Geometric mean", ""])
for implementation, value in sorted(geomeans.items()):
    lines.append(f"- `{implementation}`: `{value:.3f}x` baseline/Naux")
lines.extend(
    [
        "",
        "A ratio above `1.0` means Naux was faster. "
        "This report is publishable only when `claim eligible` is `yes`.",
        "",
    ]
)
md_path.write_text("\n".join(lines), encoding="utf-8")
PY

echo "[cross] wrote $JSON"
echo "[cross] wrote $MD"
echo "[cross] claim_eligible=$claim_eligible"
if [[ "$claim_eligible" != "true" ]]; then
    printf '[cross] claim blocker: %s\n' "${CLAIM_BLOCKERS[@]}"
fi

if [[ "$FAILED" -ne 0 ]]; then
    echo "[cross] FAILED" >&2
    exit 1
fi
if [[ "$ENFORCE_CLAIM_ENV" == "1" && "$claim_eligible" != "true" ]]; then
    echo "[cross] FAILED: claim environment is not eligible" >&2
    exit 1
fi
echo "[cross] PASS"
