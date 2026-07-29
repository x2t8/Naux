#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/target/perf}"
CPU_CORE="${CPU_CORE:-0}"
ITERS="${ITERS:-10}"
WARMUP_MS="${WARMUP_MS:-100}"
REPS="${REPS:-50}"
ENGINE="${ENGINE:-jit}"
MIN_SPEEDUP="${MIN_SPEEDUP:-0}"
MIN_SPEEDUP_SUM_DENSE="${MIN_SPEEDUP_SUM_DENSE:-}"
MIN_SPEEDUP_LIST_UPDATE="${MIN_SPEEDUP_LIST_UPDATE:-}"
MIN_SPEEDUP_DOT_PRODUCT="${MIN_SPEEDUP_DOT_PRODUCT:-}"
HARD_LIMIT_MATH_BYTES="${HARD_LIMIT_MATH_BYTES:-512}"
HARD_LIMIT_DEFAULT_BYTES="${HARD_LIMIT_DEFAULT_BYTES:-0}"
PERF_BASELINE_TSV="${PERF_BASELINE_TSV:-$ROOT_DIR/benchmarks/perf_baseline.tsv}"
SOFT_REGRESSION_PCT="${SOFT_REGRESSION_PCT:-10}"
SOFT_REGRESSION_FAIL="${SOFT_REGRESSION_FAIL:-0}"
REQUIRE_ZERO_RUNTIME_CALLS_MATH="${REQUIRE_ZERO_RUNTIME_CALLS_MATH:-1}"
REQUIRE_PATCH_COMMITS_BIMORPHIC="${REQUIRE_PATCH_COMMITS_BIMORPHIC:-0}"
PATCH_COMMIT_BENCH_FILE="${PATCH_COMMIT_BENCH_FILE:-naux-lang/examples/bench_map_get_bimorphic_phase_big.nx}"
REQUIRE_MAX_REVERT_STREAK_BIMORPHIC="${REQUIRE_MAX_REVERT_STREAK_BIMORPHIC:-0}"
MAX_REVERT_STREAK_BIMORPHIC="${MAX_REVERT_STREAK_BIMORPHIC:-3}"
REQUIRE_TEMP_ALLOC_METRICS="${REQUIRE_TEMP_ALLOC_METRICS:-0}"
TEMP_ALLOC_BENCH_FILE="${TEMP_ALLOC_BENCH_FILE:-naux-lang/examples/bench_list_temp_alloc.nx}"
MIN_TEMP_LIST_ELIDED="${MIN_TEMP_LIST_ELIDED:-0}"
MIN_TEMP_MAP_ELIDED="${MIN_TEMP_MAP_ELIDED:-0}"
MAX_TEMP_LIST_MATERIALIZED="${MAX_TEMP_LIST_MATERIALIZED:-0}"
MAX_TEMP_MAP_MATERIALIZED="${MAX_TEMP_MAP_MATERIALIZED:-0}"
MAX_TEMP_LIST_MATERIALIZED_RATIO_PCT="${MAX_TEMP_LIST_MATERIALIZED_RATIO_PCT:-10}"
MAX_TEMP_MAP_MATERIALIZED_RATIO_PCT="${MAX_TEMP_MAP_MATERIALIZED_RATIO_PCT:-10}"
REQUIRE_TEMP_MAP_ALLOC_METRICS="${REQUIRE_TEMP_MAP_ALLOC_METRICS:-1}"
TEMP_MAP_ALLOC_BENCH_FILE="${TEMP_MAP_ALLOC_BENCH_FILE:-naux-lang/examples/bench_map_temp_alloc.nx}"
MIN_TEMP_MAP_BENCH_ELIDED="${MIN_TEMP_MAP_BENCH_ELIDED:-1}"
MAX_TEMP_MAP_BENCH_MATERIALIZED="${MAX_TEMP_MAP_BENCH_MATERIALIZED:-0}"
MAX_TEMP_MAP_BENCH_MATERIALIZED_RATIO_PCT="${MAX_TEMP_MAP_BENCH_MATERIALIZED_RATIO_PCT:-10}"
ENABLE_SLOPE_GATE="${ENABLE_SLOPE_GATE:-1}"
SLOPE_GATE_SCRIPT="${SLOPE_GATE_SCRIPT:-$ROOT_DIR/scripts/perf_slope_gate.py}"
SLOPE_GATE_PRIMARY="${SLOPE_GATE_PRIMARY:-python}"
SLOPE_GATE_PRIMARY_FALLBACK_PY="${SLOPE_GATE_PRIMARY_FALLBACK_PY:-1}"
ENABLE_SLOPE_GATE_RUST_SHADOW="${ENABLE_SLOPE_GATE_RUST_SHADOW:-1}"
SLOPE_GATE_RUST_BIN="${SLOPE_GATE_RUST_BIN:-$ROOT_DIR/target/release/slope_gate}"
SLOPE_GATE_RUST_COMPARE="${SLOPE_GATE_RUST_COMPARE:-1}"
SLOPE_SHADOW_COMPARE_SCRIPT="${SLOPE_SHADOW_COMPARE_SCRIPT:-$ROOT_DIR/scripts/perf_slope_shadow_compare.py}"
SLOPE_BASELINE_TSV="${SLOPE_BASELINE_TSV:-$ROOT_DIR/benchmarks/perf_slope_baseline.tsv}"
FUSION_EXPECTATIONS_FILE="${FUSION_EXPECTATIONS_FILE:-$ROOT_DIR/scripts/fusion_expectations.json}"
FUSION_EXPECTATION_SCENARIOS="${FUSION_EXPECTATION_SCENARIOS:-map_heavy_read,map_guard_entry_heavy,map_get_mul_acc,map_get_cmp_branch}"
SLOPE_NONBLOCKING_SCENARIOS="${SLOPE_NONBLOCKING_SCENARIOS:-map_get_mul_acc}"
SLOPE_MIN_R2="${SLOPE_MIN_R2:-0.995}"
SLOPE_MAX_A_REGRESSION_PCT="${SLOPE_MAX_A_REGRESSION_PCT:-5}"
SLOPE_MAX_B_REGRESSION_PCT="${SLOPE_MAX_B_REGRESSION_PCT:-10}"
SLOPE_INSTABILITY_R2_MARGIN="${SLOPE_INSTABILITY_R2_MARGIN:-0.01}"
SLOPE_INSTABILITY_A_OVERAGE_PCT="${SLOPE_INSTABILITY_A_OVERAGE_PCT:-3}"
SLOPE_INSTABILITY_B_OVERAGE_PCT="${SLOPE_INSTABILITY_B_OVERAGE_PCT:-5}"
SLOPE_MIN_BASELINE_B_NS_FOR_GATE="${SLOPE_MIN_BASELINE_B_NS_FOR_GATE:-100000}"
SLOPE_REQUIRE_BASELINE="${SLOPE_REQUIRE_BASELINE:-1}"
SLOPE_DEFAULT_ITERS="${SLOPE_DEFAULT_ITERS:-20}"
SLOPE_DEFAULT_WARMUP_MS="${SLOPE_DEFAULT_WARMUP_MS:-100}"
SLOPE_DOT_RUNTIME_ITERS="${SLOPE_DOT_RUNTIME_ITERS:-0}"
SLOPE_DOT_RUNTIME_WARMUP_MS="${SLOPE_DOT_RUNTIME_WARMUP_MS:-0}"
SLOPE_DOT_TRACE_ITERS="${SLOPE_DOT_TRACE_ITERS:-0}"
SLOPE_DOT_TRACE_WARMUP_MS="${SLOPE_DOT_TRACE_WARMUP_MS:-0}"
SLOPE_MAP_RUNTIME_ITERS="${SLOPE_MAP_RUNTIME_ITERS:-0}"
SLOPE_MAP_RUNTIME_WARMUP_MS="${SLOPE_MAP_RUNTIME_WARMUP_MS:-0}"
SLOPE_MAP_GUARD_ENTRY_ITERS="${SLOPE_MAP_GUARD_ENTRY_ITERS:-0}"
SLOPE_MAP_GUARD_ENTRY_WARMUP_MS="${SLOPE_MAP_GUARD_ENTRY_WARMUP_MS:-0}"
SLOPE_MAP_GET_MUL_ACC_ITERS="${SLOPE_MAP_GET_MUL_ACC_ITERS:-0}"
SLOPE_MAP_GET_MUL_ACC_WARMUP_MS="${SLOPE_MAP_GET_MUL_ACC_WARMUP_MS:-0}"
SLOPE_MAP_GET_CMP_BRANCH_ITERS="${SLOPE_MAP_GET_CMP_BRANCH_ITERS:-0}"
SLOPE_MAP_GET_CMP_BRANCH_WARMUP_MS="${SLOPE_MAP_GET_CMP_BRANCH_WARMUP_MS:-0}"
SLOPE_SACRIFICIAL_WARMUP_FILE="${SLOPE_SACRIFICIAL_WARMUP_FILE:-$ROOT_DIR/naux-lang/examples/bench_dot_product.nx}"
SLOPE_SACRIFICIAL_WARMUP_N="${SLOPE_SACRIFICIAL_WARMUP_N:-1024}"
SLOPE_SACRIFICIAL_WARMUP_ITERS="${SLOPE_SACRIFICIAL_WARMUP_ITERS:-200}"
SLOPE_SACRIFICIAL_WARMUP_WARMUP_MS="${SLOPE_SACRIFICIAL_WARMUP_WARMUP_MS:-0}"
SLOPE_SACRIFICIAL_WARMUP_SETTLE_MS="${SLOPE_SACRIFICIAL_WARMUP_SETTLE_MS:-500}"
SLOPE_RUNTIME_MEASURE_RUNS="${SLOPE_RUNTIME_MEASURE_RUNS:-5}"
SLOPE_RUNTIME_TRIM_PCT="${SLOPE_RUNTIME_TRIM_PCT:-0.2}"
SLOPE_GATE_MAX_ATTEMPTS="${SLOPE_GATE_MAX_ATTEMPTS:-3}"
SLOPE_RETRYABLE_FINAL_ENFORCE="${SLOPE_RETRYABLE_FINAL_ENFORCE:-1}"
ENABLE_FUSION_RULE_GATE="${ENABLE_FUSION_RULE_GATE:-1}"
ENABLE_FIXED_COST_GATE="${ENABLE_FIXED_COST_GATE:-1}"
ENABLE_SPEEDUP_GATE="${ENABLE_SPEEDUP_GATE:-1}"
FIXED_COST_GATE_SCRIPT="${FIXED_COST_GATE_SCRIPT:-$ROOT_DIR/scripts/perf_fixed_cost_gate.py}"
FIXED_COST_REQUIRE_BASELINE="${FIXED_COST_REQUIRE_BASELINE:-1}"
FIXED_COST_LOW_N_BASELINE_TSV="${FIXED_COST_LOW_N_BASELINE_TSV:-$ROOT_DIR/benchmarks/perf_low_n_baseline.tsv}"
FIXED_COST_COLD_BASELINE_TSV="${FIXED_COST_COLD_BASELINE_TSV:-$ROOT_DIR/benchmarks/perf_cold_baseline.tsv}"
FIXED_COST_LOW_N_VALUES="${FIXED_COST_LOW_N_VALUES:-512,1024,2048}"
FIXED_COST_LOW_N_ITERS="${FIXED_COST_LOW_N_ITERS:-50}"
FIXED_COST_LOW_N_WARMUP_MS="${FIXED_COST_LOW_N_WARMUP_MS:-100}"
FIXED_COST_LOW_N_DISCARD_RUNS="${FIXED_COST_LOW_N_DISCARD_RUNS:-1}"
FIXED_COST_LOW_N_MEASURE_RUNS="${FIXED_COST_LOW_N_MEASURE_RUNS:-5}"
FIXED_COST_LOW_N_TRIM_PCT="${FIXED_COST_LOW_N_TRIM_PCT:-0.2}"
FIXED_COST_LOW_N_COOLDOWN_MS="${FIXED_COST_LOW_N_COOLDOWN_MS:-125}"
FIXED_COST_LOW_N_MAX_REG_PCT="${FIXED_COST_LOW_N_MAX_REG_PCT:-7}"
FIXED_COST_LOW_N_ABS_NS="${FIXED_COST_LOW_N_ABS_NS:-2000}"
FIXED_COST_LOW_N_ABS_NS_TINY="${FIXED_COST_LOW_N_ABS_NS_TINY:-3500}"
FIXED_COST_LOW_N_TINY_THRESHOLD="${FIXED_COST_LOW_N_TINY_THRESHOLD:-512}"
FIXED_COST_COLD_N="${FIXED_COST_COLD_N:-65536}"
FIXED_COST_COLD_SAMPLES="${FIXED_COST_COLD_SAMPLES:-11}"
FIXED_COST_COLD_MAX_REG_PCT="${FIXED_COST_COLD_MAX_REG_PCT:-12}"
FIXED_COST_COLD_ABS_NS="${FIXED_COST_COLD_ABS_NS:-100000}"
FIXED_COST_INSTABILITY_OVERAGE_PCT="${FIXED_COST_INSTABILITY_OVERAGE_PCT:-3}"
FIXED_COST_INSTABILITY_OVERAGE_NS="${FIXED_COST_INSTABILITY_OVERAGE_NS:-1000}"
FIXED_COST_GATE_MAX_ATTEMPTS="${FIXED_COST_GATE_MAX_ATTEMPTS:-3}"
FIXED_COST_PRE_COOLDOWN_MS="${FIXED_COST_PRE_COOLDOWN_MS:-500}"
ENABLE_PERF_STAT_CAPTURE="${ENABLE_PERF_STAT_CAPTURE:-1}"
PERF_STAT_N="${PERF_STAT_N:-65536}"
PERF_STAT_ITERS="${PERF_STAT_ITERS:-20}"
PERF_STAT_WARMUP_MS="${PERF_STAT_WARMUP_MS:-100}"
ENABLE_TREND_REPORT="${ENABLE_TREND_REPORT:-1}"
PERF_TREND_SCRIPT="${PERF_TREND_SCRIPT:-$ROOT_DIR/scripts/perf_trend_artifacts.py}"
PERF_TREND_HISTORY_ROOT="${PERF_TREND_HISTORY_ROOT:-$OUT_DIR/history}"
PERF_TREND_LIMIT="${PERF_TREND_LIMIT:-7}"
ENABLE_DEOPT_REPORT="${ENABLE_DEOPT_REPORT:-1}"
DEOPT_REPORT_SCRIPT="${DEOPT_REPORT_SCRIPT:-$ROOT_DIR/scripts/perf_deopt_artifacts.py}"
ENABLE_DEOPT_WARN_GATE="${ENABLE_DEOPT_WARN_GATE:-1}"
DEOPT_WARN_GATE_SCRIPT="${DEOPT_WARN_GATE_SCRIPT:-$ROOT_DIR/scripts/perf_deopt_warn_gate.py}"
DEOPT_WARN_ENFORCE="${DEOPT_WARN_ENFORCE:-0}"
DEOPT_WARN_MAX_SUMMARY_DEOPT_RATE_PCT="${DEOPT_WARN_MAX_SUMMARY_DEOPT_RATE_PCT:-1}"
DEOPT_WARN_MAX_SUMMARY_GUARD_FAIL_RATE_PCT="${DEOPT_WARN_MAX_SUMMARY_GUARD_FAIL_RATE_PCT:-0.5}"
DEOPT_WARN_MAX_TOTAL_CLONES="${DEOPT_WARN_MAX_TOTAL_CLONES:-256}"
DEOPT_WARN_MAX_SCENARIO_CLONES="${DEOPT_WARN_MAX_SCENARIO_CLONES:-8}"
DEOPT_WARN_MAX_UNKNOWN_DEOPT_REASONS="${DEOPT_WARN_MAX_UNKNOWN_DEOPT_REASONS:-0}"
DEOPT_WARN_MAX_UNKNOWN_GUARD_REASONS="${DEOPT_WARN_MAX_UNKNOWN_GUARD_REASONS:-0}"
DEOPT_WARN_MIN_TOTAL_HITS_FOR_RATE_CHECKS="${DEOPT_WARN_MIN_TOTAL_HITS_FOR_RATE_CHECKS:-1000}"
ENABLE_CLIPPY_GATE="${ENABLE_CLIPPY_GATE:-1}"
CLIPPY_PACKAGE="${CLIPPY_PACKAGE:-naux}"
CLIPPY_ALL_TARGETS="${CLIPPY_ALL_TARGETS:-1}"
CLIPPY_ALL_FEATURES="${CLIPPY_ALL_FEATURES:-0}"
CLIPPY_DENY_WARNINGS="${CLIPPY_DENY_WARNINGS:-1}"
ENABLE_MICROARCH_OBSERVE="${ENABLE_MICROARCH_OBSERVE:-1}"
ENABLE_STABILITY_WINDOW_GATE="${ENABLE_STABILITY_WINDOW_GATE:-1}"
STABILITY_WINDOW_SCRIPT="${STABILITY_WINDOW_SCRIPT:-$ROOT_DIR/scripts/perf_stability_window.py}"
STABILITY_WINDOW_SIZE="${STABILITY_WINDOW_SIZE:-$PERF_TREND_LIMIT}"
STABILITY_WINDOW_MIN_RUNS="${STABILITY_WINDOW_MIN_RUNS:-7}"
STABILITY_WINDOW_MAX_RETRYABLE_PCT="${STABILITY_WINDOW_MAX_RETRYABLE_PCT:-5}"
STABILITY_WINDOW_MAX_HARD_COUNT="${STABILITY_WINDOW_MAX_HARD_COUNT:-0}"
STABILITY_WINDOW_REQUIRED_RULES="${STABILITY_WINDOW_REQUIRED_RULES:-map_stable_mul_acc}"
STABILITY_WINDOW_MIN_RULE_HIT_PCT="${STABILITY_WINDOW_MIN_RULE_HIT_PCT:-90}"
STABILITY_WINDOW_REQUIRE_SHADOW_MATCH="${STABILITY_WINDOW_REQUIRE_SHADOW_MATCH:-1}"
STABILITY_WINDOW_MIN_SHADOW_MATCH_PCT="${STABILITY_WINDOW_MIN_SHADOW_MATCH_PCT:-100}"
STABILITY_WINDOW_FAIL_ON_INSUFFICIENT_RUNS="${STABILITY_WINDOW_FAIL_ON_INSUFFICIENT_RUNS:-0}"
STABILITY_WINDOW_ENFORCE="${STABILITY_WINDOW_ENFORCE:-0}"
ENABLE_PERF_STATUS_UPDATE="${ENABLE_PERF_STATUS_UPDATE:-1}"
PERF_STATUS_SCRIPT="${PERF_STATUS_SCRIPT:-$ROOT_DIR/scripts/update_perf_status.py}"
PERF_STATUS_FILE="${PERF_STATUS_FILE:-$OUT_DIR/perf_status.md}"
PERF_ENV_ENFORCE="${PERF_ENV_ENFORCE:-0}"
PERF_CONTROLLED_BRANCH="${PERF_CONTROLLED_BRANCH:-0}"
PERF_EXPECT_GOVERNOR="${PERF_EXPECT_GOVERNOR:-performance}"
PERF_EXPECT_INTEL_NO_TURBO="${PERF_EXPECT_INTEL_NO_TURBO:-1}"
PERF_EXPECT_AMD_BOOST="${PERF_EXPECT_AMD_BOOST:-0}"
PERF_REQUIRE_TASKSET="${PERF_REQUIRE_TASKSET:-0}"
PERF_BASELINE_FINGERPRINT_FILE="${PERF_BASELINE_FINGERPRINT_FILE:-$ROOT_DIR/benchmarks/perf_baseline_fingerprint.json}"
PERF_BASELINE_FINGERPRINT_REQUIRE="${PERF_BASELINE_FINGERPRINT_REQUIRE:-0}"
PERF_BASELINE_FINGERPRINT_ENFORCE="${PERF_BASELINE_FINGERPRINT_ENFORCE:-0}"
PERF_BASELINE_FINGERPRINT_WRITE_CURRENT="${PERF_BASELINE_FINGERPRINT_WRITE_CURRENT:-0}"
SLOPE_PRE_COOLDOWN_MS="${SLOPE_PRE_COOLDOWN_MS:-1000}"

mkdir -p "$OUT_DIR" "$OUT_DIR/bin"
# Ensure per-run artifacts are fresh; avoid stale carry-over into snapshot/trend.
rm -f \
    "$OUT_DIR/slope_report.json" \
    "$OUT_DIR/slope_report.md" \
    "$OUT_DIR/slope_report_rs_shadow.json" \
    "$OUT_DIR/slope_report_rs_shadow.md" \
    "$OUT_DIR/slope_report_rs_shadow_compare.txt" \
    "$OUT_DIR/slope_report_py_shadow.json" \
    "$OUT_DIR/slope_report_py_shadow.md" \
    "$OUT_DIR/slope_report_py_shadow_compare.txt" \
    "$OUT_DIR/slope_report_shadow_compare.json" \
    "$OUT_DIR/slope_report_shadow_compare.txt" \
    "$OUT_DIR/fixed_cost_report.json" \
    "$OUT_DIR/fixed_cost_report.md" \
    "$OUT_DIR/deopt_report.json" \
    "$OUT_DIR/deopt_report.md" \
    "$OUT_DIR/deopt_warn_report.json" \
    "$OUT_DIR/deopt_warn_report.md" \
    "$OUT_DIR/sum_dense.naux.profile.json" \
    "$OUT_DIR/list_update.naux.profile.json" \
    "$OUT_DIR/dot_product.naux.profile.json" \
    "$OUT_DIR/patch_commits_check.json" \
    "$OUT_DIR/temp_alloc_check.json" \
    "$OUT_DIR/temp_map_alloc_check.json" \
    "$OUT_DIR/stability_window_report.json" \
    "$OUT_DIR/stability_window_report.md" \
    "$OUT_DIR/trend_report.json" \
    "$OUT_DIR/trend_report.md"

PIN=()
if command -v taskset >/dev/null 2>&1; then
    PIN=(taskset -c "$CPU_CORE")
fi

cooldown_ms() {
    local label="$1"
    local ms="$2"
    if [[ "$ms" =~ ^[0-9]+$ ]] && (( ms > 0 )); then
        echo "[perf] Cooldown ${label}: ${ms}ms"
        sleep "$(awk -v ms="$ms" 'BEGIN { printf "%.3f", ms / 1000 }')"
    fi
}

run_sacrificial_slope_warmup() {
    local src="$SLOPE_SACRIFICIAL_WARMUP_FILE"
    local n="$SLOPE_SACRIFICIAL_WARMUP_N"
    local iters="$SLOPE_SACRIFICIAL_WARMUP_ITERS"
    local warmup_ms="$SLOPE_SACRIFICIAL_WARMUP_WARMUP_MS"
    local tmp_file
    tmp_file="$(mktemp "$OUT_DIR/slope-warmup.XXXXXX.nx")"
    perl -0pe \
        "s/\\\$n = \\d+/\\\$n = ${n}/; s/\\\$reps = \\d+/\\\$reps = 1/" \
        "$src" > "$tmp_file"
    echo "[perf] Running sacrificial warmup (${src##*/}, n=${n}, iters=${iters})"
    "${PIN[@]}" "$ROOT_DIR/target/release/naux" \
        dev benchrt "$tmp_file" \
        --engine="$ENGINE" \
        --iters="$iters" \
        --warmup-ms="$warmup_ms" \
        >/dev/null 2>&1 || true
    rm -f "$tmp_file"
    cooldown_ms "after sacrificial warmup" "$SLOPE_SACRIFICIAL_WARMUP_SETTLE_MS"
}

if [[ "$ENABLE_CLIPPY_GATE" == "1" ]]; then
    echo "[perf] Run clippy gate"
    clippy_cmd=(cargo clippy)
    if [[ -n "$CLIPPY_PACKAGE" ]]; then
        clippy_cmd+=(-p "$CLIPPY_PACKAGE")
    fi
    if [[ "$CLIPPY_ALL_TARGETS" == "1" ]]; then
        clippy_cmd+=(--all-targets)
    fi
    if [[ "$CLIPPY_ALL_FEATURES" == "1" ]]; then
        clippy_cmd+=(--all-features)
    fi
    if [[ "$CLIPPY_DENY_WARNINGS" == "1" ]]; then
        clippy_cmd+=(-- -D warnings)
    fi
    if ! "${clippy_cmd[@]}"; then
        echo "[perf] clippy gate failed" >&2
        exit 1
    fi
fi

BENCH_NAMES=("sum_dense" "list_update" "dot_product")
NAUX_FILES=(
    "naux-lang/examples/bench_sum_dense.nx"
    "naux-lang/examples/bench_list_update.nx"
    "naux-lang/examples/bench_dot_product.nx"
)
C_SRCS=(
    "benchmarks/c/bench_sum_dense.c"
    "benchmarks/c/bench_list_update.c"
    "benchmarks/c/bench_dot_product.c"
)
C_BINS=(
    "bench_sum_dense"
    "bench_list_update"
    "bench_dot_product"
)

echo "[perf] Build release with native CPU"
RUSTFLAGS="-C target-cpu=native" cargo build -p naux --release
SLOPE_GATE_RUST_SHADOW_READY=0
NEED_RUST_SLOPE_GATE=0
if [[ "$ENABLE_SLOPE_GATE" == "1" ]]; then
    if [[ "$SLOPE_GATE_PRIMARY" == "rust" || "$ENABLE_SLOPE_GATE_RUST_SHADOW" == "1" ]]; then
        NEED_RUST_SLOPE_GATE=1
    fi
fi
if [[ "$NEED_RUST_SLOPE_GATE" == "1" ]]; then
    echo "[perf] Build Rust slope gate"
    set +e
    cargo build -p perf-gates --release
    slope_rs_build_rc=$?
    set -e
    if [[ "$slope_rs_build_rc" -eq 0 && -x "$SLOPE_GATE_RUST_BIN" ]]; then
        SLOPE_GATE_RUST_SHADOW_READY=1
    else
        echo "[perf] WARN: Rust slope gate shadow disabled (build rc=${slope_rs_build_rc}, bin=${SLOPE_GATE_RUST_BIN})"
    fi
fi

if [[ "$ENABLE_SPEEDUP_GATE" == "1" ]]; then
    echo "[perf] Build C baselines"
    for i in "${!C_SRCS[@]}"; do
        cc -O3 -march=native -o "$OUT_DIR/bin/${C_BINS[$i]}" "$ROOT_DIR/${C_SRCS[$i]}" -lm
    done
fi

parse_metric() {
    local key="$1"
    local data="$2"
    echo "$data" | sed -n "s/.*$key=\([0-9][0-9]*\).*/\1/p" | head -n1
}

parse_trace_hot_code_avg() {
    local data="$1"
    local hot
    hot="$(echo "$data" | sed -n 's/.*hot_code(min\/avg\/max)=[0-9][0-9]*\/\([0-9][0-9]*\(\.[0-9][0-9]*\)\?\)\/[0-9][0-9]*.*/\1/p' | head -n1)"
    if [[ -n "$hot" ]]; then
        echo "$hot"
    else
        # Backward compatibility with older bench output that only reports total code bytes.
        echo "$data" | sed -n 's/.*code(min\/avg\/max)=[0-9][0-9]*\/\([0-9][0-9]*\(\.[0-9][0-9]*\)\?\)\/[0-9][0-9]*.*/\1/p' | head -n1
    fi
}

parse_json_int() {
    local key="$1"
    local data="$2"
    echo "$data" | sed -n "s/.*\"$key\":\\([0-9][0-9]*\\).*/\\1/p" | head -n1
}

parse_json_float() {
    local key="$1"
    local data="$2"
    echo "$data" | sed -n "s/.*\"$key\":\\([0-9][0-9]*\\(\\.[0-9][0-9]*\\)\\?\\).*/\\1/p" | head -n1
}

update_perf_status_best_effort() {
    if [[ "$ENABLE_PERF_STATUS_UPDATE" != "1" ]]; then
        return 0
    fi
    if [[ ! -f "$PERF_STATUS_SCRIPT" ]]; then
        echo "[perf] WARN: perf status script not found: $PERF_STATUS_SCRIPT"
        return 0
    fi
    set +e
    python3 "$PERF_STATUS_SCRIPT" \
        --trend-json "$OUT_DIR/trend_report.json" \
        --stability-json "$OUT_DIR/stability_window_report.json" \
        --slope-json "$OUT_DIR/slope_report.json" \
        --fixed-cost-json "$OUT_DIR/fixed_cost_report.json" \
        --deopt-warn-json "$OUT_DIR/deopt_warn_report.json" \
        --out "$PERF_STATUS_FILE"
    perf_status_rc=$?
    set -e
    if [[ "$perf_status_rc" -ne 0 ]]; then
        echo "[perf] WARN: perf status update failed (rc=${perf_status_rc})"
    fi
}

speedup() {
    local c_ns="$1"
    local naux_ns="$2"
    awk -v c="$c_ns" -v n="$naux_ns" 'BEGIN { if (n == 0) print "0.000"; else printf "%.3f", c / n }'
}

ge_float() {
    local a="$1"
    local b="$2"
    awk -v a="$a" -v b="$b" 'BEGIN { if (a + 0 >= b + 0) print 1; else print 0 }'
}

hard_limit_for() {
    local name="$1"
    case "$name" in
        sum_dense|dot_product)
            echo "$HARD_LIMIT_MATH_BYTES"
            ;;
        *)
            echo "$HARD_LIMIT_DEFAULT_BYTES"
            ;;
    esac
}

min_speedup_for() {
    local name="$1"
    case "$name" in
        sum_dense)
            [[ -n "$MIN_SPEEDUP_SUM_DENSE" ]] && echo "$MIN_SPEEDUP_SUM_DENSE" || echo "$MIN_SPEEDUP"
            ;;
        list_update)
            [[ -n "$MIN_SPEEDUP_LIST_UPDATE" ]] && echo "$MIN_SPEEDUP_LIST_UPDATE" || echo "$MIN_SPEEDUP"
            ;;
        dot_product)
            [[ -n "$MIN_SPEEDUP_DOT_PRODUCT" ]] && echo "$MIN_SPEEDUP_DOT_PRODUCT" || echo "$MIN_SPEEDUP"
            ;;
        *)
            echo "$MIN_SPEEDUP"
            ;;
    esac
}

baseline_code_for() {
    local name="$1"
    local file="$2"
    if [[ ! -f "$file" ]]; then
        return 0
    fi
    awk -v n="$name" 'NF >= 2 && $1 !~ /^#/ && $1 == n { print $2; exit }' "$file"
}

gt_float() {
    local a="$1"
    local b="$2"
    awk -v a="$a" -v b="$b" 'BEGIN { if (a + 0 > b + 0) print 1; else print 0 }'
}

mul_float() {
    local a="$1"
    local factor="$2"
    awk -v a="$a" -v f="$factor" 'BEGIN { printf "%.3f", a * f }'
}

calc_ratio_pct() {
    local materialized="$1"
    local elided="$2"
    awk -v m="$materialized" -v e="$elided" 'BEGIN {
        if (e + 0 <= 0) {
            if (m + 0 > 0) print "100.0000";
            else print "0.0000";
        } else {
            printf "%.4f", (m / e) * 100.0;
        }
    }'
}

read_sysfs_trimmed() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        return 1
    fi
    tr -d '[:space:]' < "$path"
}

append_env_note() {
    local msg="$1"
    if [[ -z "${PERF_ENV_NOTES:-}" ]]; then
        PERF_ENV_NOTES="$msg"
    else
        PERF_ENV_NOTES="$PERF_ENV_NOTES; $msg"
    fi
}

append_baseline_fp_note() {
    local msg="$1"
    if [[ -z "${PERF_BASELINE_FINGERPRINT_NOTES:-}" ]]; then
        PERF_BASELINE_FINGERPRINT_NOTES="$msg"
    else
        PERF_BASELINE_FINGERPRINT_NOTES="$PERF_BASELINE_FINGERPRINT_NOTES; $msg"
    fi
}

read_cpu_model() {
    if [[ -r /proc/cpuinfo ]]; then
        awk -F: '/model name/ { gsub(/^[[:space:]]+/, "", $2); print $2; exit }' /proc/cpuinfo
        return 0
    fi
    if command -v lscpu >/dev/null 2>&1; then
        lscpu | awk -F: '/Model name/ { gsub(/^[[:space:]]+/, "", $2); print $2; exit }'
        return 0
    fi
    return 1
}

json_escape() {
    local raw="${1:-}"
    printf '%s' "$raw" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read())[1:-1])'
}

TSV="$OUT_DIR/perf.tsv"
JSON="$OUT_DIR/perf_report.json"
MD="$OUT_DIR/perf_report.md"
: > "$TSV"

FAILED=0

PERF_ENV_STATUS="pass"
PERF_ENV_NOTES=""
PERF_ENV_GOVERNOR_ACTUAL="unavailable"
PERF_ENV_TURBO_SOURCE="unavailable"
PERF_ENV_TURBO_ACTUAL="unavailable"
PERF_ENV_MISMATCH=0
PERF_ENV_CPU_MODEL="unavailable"
PERF_BASELINE_FINGERPRINT_STATUS="pass"
PERF_BASELINE_FINGERPRINT_NOTES=""
PERF_BASELINE_FINGERPRINT_MISMATCH=0

if [[ "$PERF_REQUIRE_TASKSET" == "1" && ${#PIN[@]} -eq 0 ]]; then
    PERF_ENV_MISMATCH=1
    append_env_note "taskset unavailable while PERF_REQUIRE_TASKSET=1"
fi

gov_path="/sys/devices/system/cpu/cpu${CPU_CORE}/cpufreq/scaling_governor"
if gov_val="$(read_sysfs_trimmed "$gov_path" 2>/dev/null)"; then
    PERF_ENV_GOVERNOR_ACTUAL="$gov_val"
    if [[ -n "$PERF_EXPECT_GOVERNOR" && "$gov_val" != "$PERF_EXPECT_GOVERNOR" ]]; then
        PERF_ENV_MISMATCH=1
        append_env_note "cpu${CPU_CORE} governor=$gov_val expected=$PERF_EXPECT_GOVERNOR"
    fi
else
    append_env_note "missing $gov_path"
    if [[ -n "$PERF_EXPECT_GOVERNOR" ]]; then
        PERF_ENV_MISMATCH=1
    fi
fi

intel_no_turbo_path="/sys/devices/system/cpu/intel_pstate/no_turbo"
amd_boost_path="/sys/devices/system/cpu/cpufreq/boost"
if intel_val="$(read_sysfs_trimmed "$intel_no_turbo_path" 2>/dev/null)"; then
    PERF_ENV_TURBO_SOURCE="intel_pstate/no_turbo"
    PERF_ENV_TURBO_ACTUAL="$intel_val"
    if [[ -n "$PERF_EXPECT_INTEL_NO_TURBO" && "$intel_val" != "$PERF_EXPECT_INTEL_NO_TURBO" ]]; then
        PERF_ENV_MISMATCH=1
        append_env_note "intel no_turbo=$intel_val expected=$PERF_EXPECT_INTEL_NO_TURBO"
    fi
elif amd_val="$(read_sysfs_trimmed "$amd_boost_path" 2>/dev/null)"; then
    PERF_ENV_TURBO_SOURCE="cpufreq/boost"
    PERF_ENV_TURBO_ACTUAL="$amd_val"
    if [[ -n "$PERF_EXPECT_AMD_BOOST" && "$amd_val" != "$PERF_EXPECT_AMD_BOOST" ]]; then
        PERF_ENV_MISMATCH=1
        append_env_note "amd boost=$amd_val expected=$PERF_EXPECT_AMD_BOOST"
    fi
else
    append_env_note "missing turbo control sysfs (intel_pstate/no_turbo or cpufreq/boost)"
    if [[ -n "$PERF_EXPECT_INTEL_NO_TURBO" || -n "$PERF_EXPECT_AMD_BOOST" ]]; then
        PERF_ENV_MISMATCH=1
    fi
fi

if cpu_model_val="$(read_cpu_model 2>/dev/null)"; then
    PERF_ENV_CPU_MODEL="$cpu_model_val"
else
    append_env_note "cpu model unavailable"
    if [[ "$PERF_ENV_ENFORCE" == "1" ]]; then
        PERF_ENV_MISMATCH=1
    fi
fi

if [[ "$PERF_ENV_MISMATCH" == "1" ]]; then
    if [[ "$PERF_ENV_ENFORCE" == "1" ]]; then
        PERF_ENV_STATUS="fail"
        echo "::error::perf environment preflight failed: $PERF_ENV_NOTES"
        exit 1
    else
        PERF_ENV_STATUS="warn"
        echo "[perf] WARN: perf environment preflight mismatch: $PERF_ENV_NOTES"
    fi
fi
echo "[perf] perf env preflight status: $PERF_ENV_STATUS (governor=$PERF_ENV_GOVERNOR_ACTUAL, turbo=$PERF_ENV_TURBO_SOURCE:$PERF_ENV_TURBO_ACTUAL)"

if [[ "$PERF_BASELINE_FINGERPRINT_WRITE_CURRENT" == "1" ]]; then
    mkdir -p "$(dirname "$PERF_BASELINE_FINGERPRINT_FILE")"
    cat > "$PERF_BASELINE_FINGERPRINT_FILE" <<EOF
{
  "cpu_model": "$(json_escape "$PERF_ENV_CPU_MODEL")",
  "cpu_core": "$CPU_CORE",
  "governor": "$(json_escape "$PERF_ENV_GOVERNOR_ACTUAL")",
  "turbo_source": "$(json_escape "$PERF_ENV_TURBO_SOURCE")",
  "turbo_value": "$(json_escape "$PERF_ENV_TURBO_ACTUAL")"
}
EOF
    PERF_BASELINE_FINGERPRINT_STATUS="updated"
    append_baseline_fp_note "wrote current fingerprint to $PERF_BASELINE_FINGERPRINT_FILE"
fi

if [[ "$PERF_BASELINE_FINGERPRINT_WRITE_CURRENT" != "1" ]]; then
    if [[ -f "$PERF_BASELINE_FINGERPRINT_FILE" ]]; then
        set +e
        fp_cmp_msg="$(python3 - "$PERF_BASELINE_FINGERPRINT_FILE" "$PERF_ENV_CPU_MODEL" "$CPU_CORE" "$PERF_ENV_GOVERNOR_ACTUAL" "$PERF_ENV_TURBO_SOURCE" "$PERF_ENV_TURBO_ACTUAL" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
actual = {
    "cpu_model": sys.argv[2],
    "cpu_core": str(sys.argv[3]),
    "governor": sys.argv[4],
    "turbo_source": sys.argv[5],
    "turbo_value": sys.argv[6],
}
try:
    expected = json.loads(path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"invalid fingerprint json: {exc}")
    sys.exit(2)

errors = []
for key, cur in actual.items():
    exp = expected.get(key)
    if exp is None:
        errors.append(f"missing key '{key}'")
        continue
    if str(exp) != str(cur):
        errors.append(f"{key}={cur} expected={exp}")

if errors:
    print("; ".join(errors))
    sys.exit(1)
sys.exit(0)
PY
)"
        fp_cmp_rc=$?
        set -e
        if [[ "$fp_cmp_rc" -ne 0 ]]; then
            PERF_BASELINE_FINGERPRINT_MISMATCH=1
            PERF_BASELINE_FINGERPRINT_STATUS="mismatch"
            append_baseline_fp_note "$fp_cmp_msg"
        fi
    else
        if [[ "$PERF_BASELINE_FINGERPRINT_REQUIRE" == "1" ]]; then
            PERF_BASELINE_FINGERPRINT_MISMATCH=1
            PERF_BASELINE_FINGERPRINT_STATUS="missing"
            append_baseline_fp_note "missing fingerprint file: $PERF_BASELINE_FINGERPRINT_FILE"
        else
            PERF_BASELINE_FINGERPRINT_STATUS="missing"
            append_baseline_fp_note "missing fingerprint file (allowed): $PERF_BASELINE_FINGERPRINT_FILE"
        fi
    fi
fi

if [[ "$PERF_BASELINE_FINGERPRINT_MISMATCH" == "1" ]]; then
    if [[ "$PERF_BASELINE_FINGERPRINT_ENFORCE" == "1" ]]; then
        echo "::error::baseline fingerprint check failed: $PERF_BASELINE_FINGERPRINT_NOTES"
        exit 1
    fi
    echo "[perf] WARN: baseline fingerprint mismatch: $PERF_BASELINE_FINGERPRINT_NOTES"
    if [[ "$PERF_BASELINE_FINGERPRINT_STATUS" == "pass" ]]; then
        PERF_BASELINE_FINGERPRINT_STATUS="warn"
    fi
fi
echo "[perf] baseline fingerprint status: $PERF_BASELINE_FINGERPRINT_STATUS ($PERF_BASELINE_FINGERPRINT_FILE)"

if [[ "$ENABLE_FIXED_COST_GATE" == "1" ]]; then
    cooldown_ms "before fixed-cost gate" "$FIXED_COST_PRE_COOLDOWN_MS"
    echo "[perf] Run fixed-cost gate (low-n + cold-start + perf-stat artifact)"
    fixed_args=(
        "$FIXED_COST_GATE_SCRIPT"
        --root "$ROOT_DIR"
        --naux-bin "$ROOT_DIR/target/release/naux"
        --cpu-core "$CPU_CORE"
        --engine "$ENGINE"
        --low-n-values "$FIXED_COST_LOW_N_VALUES"
        --low-n-iters "$FIXED_COST_LOW_N_ITERS"
        --low-n-warmup-ms "$FIXED_COST_LOW_N_WARMUP_MS"
        --low-n-discard-runs "$FIXED_COST_LOW_N_DISCARD_RUNS"
        --low-n-measure-runs "$FIXED_COST_LOW_N_MEASURE_RUNS"
        --low-n-trim-pct "$FIXED_COST_LOW_N_TRIM_PCT"
        --low-n-cooldown-ms "$FIXED_COST_LOW_N_COOLDOWN_MS"
        --low-n-max-reg-pct "$FIXED_COST_LOW_N_MAX_REG_PCT"
        --low-n-abs-ns "$FIXED_COST_LOW_N_ABS_NS"
        --low-n-abs-ns-tiny "$FIXED_COST_LOW_N_ABS_NS_TINY"
        --low-n-tiny-threshold "$FIXED_COST_LOW_N_TINY_THRESHOLD"
        --cold-n "$FIXED_COST_COLD_N"
        --cold-samples "$FIXED_COST_COLD_SAMPLES"
        --cold-max-reg-pct "$FIXED_COST_COLD_MAX_REG_PCT"
        --cold-abs-ns "$FIXED_COST_COLD_ABS_NS"
        --instability-overage-pct "$FIXED_COST_INSTABILITY_OVERAGE_PCT"
        --instability-overage-ns "$FIXED_COST_INSTABILITY_OVERAGE_NS"
        --low-n-baseline "$FIXED_COST_LOW_N_BASELINE_TSV"
        --cold-baseline "$FIXED_COST_COLD_BASELINE_TSV"
        --perf-stat-n "$PERF_STAT_N"
        --perf-stat-iters "$PERF_STAT_ITERS"
        --perf-stat-warmup-ms "$PERF_STAT_WARMUP_MS"
        --out-json "$OUT_DIR/fixed_cost_report.json"
        --out-md "$OUT_DIR/fixed_cost_report.md"
    )
    if [[ "$FIXED_COST_REQUIRE_BASELINE" == "1" ]]; then
        fixed_args+=(--require-baseline)
    fi
    if [[ "$ENABLE_PERF_STAT_CAPTURE" == "1" ]]; then
        fixed_args+=(--enable-perf-stat)
        if [[ "$ENABLE_MICROARCH_OBSERVE" == "1" ]]; then
            fixed_args+=(--enable-microarch-observe)
        fi
    fi
    fixed_ok=0
    fixed_attempt=1
    while (( fixed_attempt <= FIXED_COST_GATE_MAX_ATTEMPTS )); do
        echo "[perf] fixed-cost gate attempt ${fixed_attempt}/${FIXED_COST_GATE_MAX_ATTEMPTS}"
        set +e
        "${fixed_args[@]}"
        fixed_rc=$?
        set -e
        if [[ "$fixed_rc" -eq 0 ]]; then
            fixed_ok=1
            break
        fi
        if [[ "$fixed_rc" -eq 2 && "$fixed_attempt" -lt "$FIXED_COST_GATE_MAX_ATTEMPTS" ]]; then
            echo "[perf] fixed-cost instability detected, rerunning..."
            fixed_attempt=$((fixed_attempt + 1))
            continue
        fi
        fixed_attempt=$((fixed_attempt + 1))
        break
    done
    if [[ "$fixed_ok" != "1" ]]; then
        FAILED=1
    fi
fi

if [[ "$ENABLE_SLOPE_GATE" == "1" ]]; then
    run_sacrificial_slope_warmup
    cooldown_ms "before slope gate" "$SLOPE_PRE_COOLDOWN_MS"
    echo "[perf] Run slope regression gate"
    slope_args_py=(
        "$SLOPE_GATE_SCRIPT"
        --root "$ROOT_DIR"
        --naux-bin "$ROOT_DIR/target/release/naux"
        --cpu-core "$CPU_CORE"
        --engine "$ENGINE"
        --default-iters "$SLOPE_DEFAULT_ITERS"
        --default-warmup-ms "$SLOPE_DEFAULT_WARMUP_MS"
        --dot-runtime-iters "$SLOPE_DOT_RUNTIME_ITERS"
        --dot-runtime-warmup-ms "$SLOPE_DOT_RUNTIME_WARMUP_MS"
        --dot-trace-iters "$SLOPE_DOT_TRACE_ITERS"
        --dot-trace-warmup-ms "$SLOPE_DOT_TRACE_WARMUP_MS"
        --map-runtime-iters "$SLOPE_MAP_RUNTIME_ITERS"
        --map-runtime-warmup-ms "$SLOPE_MAP_RUNTIME_WARMUP_MS"
        --map-guard-entry-iters "$SLOPE_MAP_GUARD_ENTRY_ITERS"
        --map-guard-entry-warmup-ms "$SLOPE_MAP_GUARD_ENTRY_WARMUP_MS"
        --map-get-mul-acc-iters "$SLOPE_MAP_GET_MUL_ACC_ITERS"
        --map-get-mul-acc-warmup-ms "$SLOPE_MAP_GET_MUL_ACC_WARMUP_MS"
        --map-get-cmp-branch-iters "$SLOPE_MAP_GET_CMP_BRANCH_ITERS"
        --map-get-cmp-branch-warmup-ms "$SLOPE_MAP_GET_CMP_BRANCH_WARMUP_MS"
        --slope-baseline "$SLOPE_BASELINE_TSV"
        --fusion-expectations "$FUSION_EXPECTATIONS_FILE"
        --require-fusion-expectation-scenarios "$FUSION_EXPECTATION_SCENARIOS"
        --nonblocking-scenarios "$SLOPE_NONBLOCKING_SCENARIOS"
        --min-r2 "$SLOPE_MIN_R2"
        --max-a-regression-pct "$SLOPE_MAX_A_REGRESSION_PCT"
        --max-b-regression-pct "$SLOPE_MAX_B_REGRESSION_PCT"
        --instability-r2-margin "$SLOPE_INSTABILITY_R2_MARGIN"
        --instability-a-overage-pct "$SLOPE_INSTABILITY_A_OVERAGE_PCT"
        --instability-b-overage-pct "$SLOPE_INSTABILITY_B_OVERAGE_PCT"
        --min-baseline-b-ns-for-gate "$SLOPE_MIN_BASELINE_B_NS_FOR_GATE"
        --runtime-measure-runs "$SLOPE_RUNTIME_MEASURE_RUNS"
        --runtime-trim-pct "$SLOPE_RUNTIME_TRIM_PCT"
        --baseline-fingerprint-file "$PERF_BASELINE_FINGERPRINT_FILE"
        --baseline-fingerprint-status "$PERF_BASELINE_FINGERPRINT_STATUS"
        --baseline-fingerprint-notes "$PERF_BASELINE_FINGERPRINT_NOTES"
        --cpu-model "$PERF_ENV_CPU_MODEL"
        --out-json "$OUT_DIR/slope_report.json"
        --out-md "$OUT_DIR/slope_report.md"
    )
    slope_args_rs_primary=(
        "$SLOPE_GATE_RUST_BIN"
        --root "$ROOT_DIR"
        --naux-bin "$ROOT_DIR/target/release/naux"
        --cpu-core "$CPU_CORE"
        --engine "$ENGINE"
        --default-iters "$SLOPE_DEFAULT_ITERS"
        --default-warmup-ms "$SLOPE_DEFAULT_WARMUP_MS"
        --dot-runtime-iters "$SLOPE_DOT_RUNTIME_ITERS"
        --dot-runtime-warmup-ms "$SLOPE_DOT_RUNTIME_WARMUP_MS"
        --dot-trace-iters "$SLOPE_DOT_TRACE_ITERS"
        --dot-trace-warmup-ms "$SLOPE_DOT_TRACE_WARMUP_MS"
        --map-runtime-iters "$SLOPE_MAP_RUNTIME_ITERS"
        --map-runtime-warmup-ms "$SLOPE_MAP_RUNTIME_WARMUP_MS"
        --map-guard-entry-iters "$SLOPE_MAP_GUARD_ENTRY_ITERS"
        --map-guard-entry-warmup-ms "$SLOPE_MAP_GUARD_ENTRY_WARMUP_MS"
        --map-get-mul-acc-iters "$SLOPE_MAP_GET_MUL_ACC_ITERS"
        --map-get-mul-acc-warmup-ms "$SLOPE_MAP_GET_MUL_ACC_WARMUP_MS"
        --map-get-cmp-branch-iters "$SLOPE_MAP_GET_CMP_BRANCH_ITERS"
        --map-get-cmp-branch-warmup-ms "$SLOPE_MAP_GET_CMP_BRANCH_WARMUP_MS"
        --slope-baseline "$SLOPE_BASELINE_TSV"
        --fusion-expectations "$FUSION_EXPECTATIONS_FILE"
        --require-fusion-expectation-scenarios "$FUSION_EXPECTATION_SCENARIOS"
        --nonblocking-scenarios "$SLOPE_NONBLOCKING_SCENARIOS"
        --min-r2 "$SLOPE_MIN_R2"
        --max-a-regression-pct "$SLOPE_MAX_A_REGRESSION_PCT"
        --max-b-regression-pct "$SLOPE_MAX_B_REGRESSION_PCT"
        --instability-r2-margin "$SLOPE_INSTABILITY_R2_MARGIN"
        --instability-a-overage-pct "$SLOPE_INSTABILITY_A_OVERAGE_PCT"
        --instability-b-overage-pct "$SLOPE_INSTABILITY_B_OVERAGE_PCT"
        --min-baseline-b-ns-for-gate "$SLOPE_MIN_BASELINE_B_NS_FOR_GATE"
        --runtime-measure-runs "$SLOPE_RUNTIME_MEASURE_RUNS"
        --runtime-trim-pct "$SLOPE_RUNTIME_TRIM_PCT"
        --baseline-fingerprint-file "$PERF_BASELINE_FINGERPRINT_FILE"
        --baseline-fingerprint-status "$PERF_BASELINE_FINGERPRINT_STATUS"
        --baseline-fingerprint-notes "$PERF_BASELINE_FINGERPRINT_NOTES"
        --cpu-model "$PERF_ENV_CPU_MODEL"
        --out-json "$OUT_DIR/slope_report.json"
        --out-md "$OUT_DIR/slope_report.md"
    )
    if [[ "$SLOPE_REQUIRE_BASELINE" == "1" ]]; then
        slope_args_py+=(--require-baseline)
        slope_args_rs_primary+=(--require-baseline)
    fi
    if [[ "$ENABLE_FUSION_RULE_GATE" != "1" ]]; then
        slope_args_py+=(--disable-fusion-rule-gate)
        slope_args_rs_primary+=(--disable-fusion-rule-gate)
    fi

    primary_choice="$SLOPE_GATE_PRIMARY"
    run_primary=1
    if [[ "$primary_choice" != "python" && "$primary_choice" != "rust" ]]; then
        echo "::error::invalid SLOPE_GATE_PRIMARY='$SLOPE_GATE_PRIMARY' (expected python|rust)"
        FAILED=1
        run_primary=0
    fi
    if [[ "$primary_choice" == "rust" && "$SLOPE_GATE_RUST_SHADOW_READY" != "1" ]]; then
        if [[ "$SLOPE_GATE_PRIMARY_FALLBACK_PY" == "1" ]]; then
            echo "[perf] WARN: Rust slope gate primary requested but binary not ready; fallback to Python primary"
            primary_choice="python"
        else
            echo "::error::Rust slope gate primary requested but binary not ready"
            FAILED=1
            run_primary=0
        fi
    fi

    if [[ "$run_primary" == "1" ]]; then
        echo "[perf] slope gate primary: ${primary_choice}"
        slope_ok=0
        slope_last_rc=0
        attempt=1
        while (( attempt <= SLOPE_GATE_MAX_ATTEMPTS )); do
            echo "[perf] slope gate attempt ${attempt}/${SLOPE_GATE_MAX_ATTEMPTS}"
            set +e
            if [[ "$primary_choice" == "rust" ]]; then
                "${slope_args_rs_primary[@]}"
            else
                "${slope_args_py[@]}"
            fi
            rc=$?
            slope_last_rc="$rc"
            set -e
            if [[ "$rc" -eq 0 ]]; then
                slope_ok=1
                break
            fi
            if [[ "$rc" -eq 2 && "$attempt" -lt "$SLOPE_GATE_MAX_ATTEMPTS" ]]; then
                echo "[perf] slope instability detected, rerunning..."
                attempt=$((attempt + 1))
                continue
            fi
            attempt=$((attempt + 1))
            break
        done
        if [[ "$slope_ok" != "1" ]]; then
            # Retryable slope failures are measurement-noise candidates; callers can opt to warn
            # after exhausting retries while still preserving hard failures as blocking.
            if [[ "$slope_last_rc" -eq 2 && "$SLOPE_RETRYABLE_FINAL_ENFORCE" != "1" ]]; then
                echo "[perf] WARN: slope gate remained retryable after ${SLOPE_GATE_MAX_ATTEMPTS} attempts (continue with SLOPE_RETRYABLE_FINAL_ENFORCE=0)"
            else
                FAILED=1
            fi
        fi
    fi

    if [[ "$ENABLE_SLOPE_GATE_RUST_SHADOW" == "1" && "$run_primary" == "1" ]]; then
        shadow_name=""
        shadow_json=""
        shadow_md=""
        shadow_cmp_txt=""
        slope_args_shadow=()

        if [[ "$primary_choice" == "python" ]]; then
            if [[ "$SLOPE_GATE_RUST_SHADOW_READY" == "1" ]]; then
                shadow_name="rust"
                shadow_json="$OUT_DIR/slope_report_rs_shadow.json"
                shadow_md="$OUT_DIR/slope_report_rs_shadow.md"
                shadow_cmp_txt="$OUT_DIR/slope_report_rs_shadow_compare.txt"
                slope_args_shadow=(
                    "$SLOPE_GATE_RUST_BIN"
                    --root "$ROOT_DIR"
                    --naux-bin "$ROOT_DIR/target/release/naux"
                    --cpu-core "$CPU_CORE"
                    --engine "$ENGINE"
                    --default-iters "$SLOPE_DEFAULT_ITERS"
                    --default-warmup-ms "$SLOPE_DEFAULT_WARMUP_MS"
                    --dot-runtime-iters "$SLOPE_DOT_RUNTIME_ITERS"
                    --dot-runtime-warmup-ms "$SLOPE_DOT_RUNTIME_WARMUP_MS"
                    --dot-trace-iters "$SLOPE_DOT_TRACE_ITERS"
                    --dot-trace-warmup-ms "$SLOPE_DOT_TRACE_WARMUP_MS"
                    --map-runtime-iters "$SLOPE_MAP_RUNTIME_ITERS"
                    --map-runtime-warmup-ms "$SLOPE_MAP_RUNTIME_WARMUP_MS"
                    --map-guard-entry-iters "$SLOPE_MAP_GUARD_ENTRY_ITERS"
                    --map-guard-entry-warmup-ms "$SLOPE_MAP_GUARD_ENTRY_WARMUP_MS"
                    --map-get-mul-acc-iters "$SLOPE_MAP_GET_MUL_ACC_ITERS"
                    --map-get-mul-acc-warmup-ms "$SLOPE_MAP_GET_MUL_ACC_WARMUP_MS"
                    --map-get-cmp-branch-iters "$SLOPE_MAP_GET_CMP_BRANCH_ITERS"
                    --map-get-cmp-branch-warmup-ms "$SLOPE_MAP_GET_CMP_BRANCH_WARMUP_MS"
                    --slope-baseline "$SLOPE_BASELINE_TSV"
                    --fusion-expectations "$FUSION_EXPECTATIONS_FILE"
                    --require-fusion-expectation-scenarios "$FUSION_EXPECTATION_SCENARIOS"
                    --nonblocking-scenarios "$SLOPE_NONBLOCKING_SCENARIOS"
                    --min-r2 "$SLOPE_MIN_R2"
                    --max-a-regression-pct "$SLOPE_MAX_A_REGRESSION_PCT"
                    --max-b-regression-pct "$SLOPE_MAX_B_REGRESSION_PCT"
                    --instability-r2-margin "$SLOPE_INSTABILITY_R2_MARGIN"
                    --instability-a-overage-pct "$SLOPE_INSTABILITY_A_OVERAGE_PCT"
                    --instability-b-overage-pct "$SLOPE_INSTABILITY_B_OVERAGE_PCT"
                    --min-baseline-b-ns-for-gate "$SLOPE_MIN_BASELINE_B_NS_FOR_GATE"
                    --runtime-measure-runs "$SLOPE_RUNTIME_MEASURE_RUNS"
                    --runtime-trim-pct "$SLOPE_RUNTIME_TRIM_PCT"
                    --baseline-fingerprint-file "$PERF_BASELINE_FINGERPRINT_FILE"
                    --baseline-fingerprint-status "$PERF_BASELINE_FINGERPRINT_STATUS"
                    --baseline-fingerprint-notes "$PERF_BASELINE_FINGERPRINT_NOTES"
                    --cpu-model "$PERF_ENV_CPU_MODEL"
                    --out-json "$shadow_json"
                    --out-md "$shadow_md"
                )
            else
                echo "[perf] WARN: skip Rust slope gate shadow (not ready)"
            fi
        else
            shadow_name="python"
            shadow_json="$OUT_DIR/slope_report_py_shadow.json"
            shadow_md="$OUT_DIR/slope_report_py_shadow.md"
            shadow_cmp_txt="$OUT_DIR/slope_report_py_shadow_compare.txt"
            slope_args_shadow=(
                "$SLOPE_GATE_SCRIPT"
                --root "$ROOT_DIR"
                --naux-bin "$ROOT_DIR/target/release/naux"
                --cpu-core "$CPU_CORE"
                --engine "$ENGINE"
                --default-iters "$SLOPE_DEFAULT_ITERS"
                --default-warmup-ms "$SLOPE_DEFAULT_WARMUP_MS"
                --dot-runtime-iters "$SLOPE_DOT_RUNTIME_ITERS"
                --dot-runtime-warmup-ms "$SLOPE_DOT_RUNTIME_WARMUP_MS"
                --dot-trace-iters "$SLOPE_DOT_TRACE_ITERS"
                --dot-trace-warmup-ms "$SLOPE_DOT_TRACE_WARMUP_MS"
                --map-runtime-iters "$SLOPE_MAP_RUNTIME_ITERS"
                --map-runtime-warmup-ms "$SLOPE_MAP_RUNTIME_WARMUP_MS"
                --map-guard-entry-iters "$SLOPE_MAP_GUARD_ENTRY_ITERS"
                --map-guard-entry-warmup-ms "$SLOPE_MAP_GUARD_ENTRY_WARMUP_MS"
                --map-get-mul-acc-iters "$SLOPE_MAP_GET_MUL_ACC_ITERS"
                --map-get-mul-acc-warmup-ms "$SLOPE_MAP_GET_MUL_ACC_WARMUP_MS"
                --map-get-cmp-branch-iters "$SLOPE_MAP_GET_CMP_BRANCH_ITERS"
                --map-get-cmp-branch-warmup-ms "$SLOPE_MAP_GET_CMP_BRANCH_WARMUP_MS"
                --slope-baseline "$SLOPE_BASELINE_TSV"
                --fusion-expectations "$FUSION_EXPECTATIONS_FILE"
                --require-fusion-expectation-scenarios "$FUSION_EXPECTATION_SCENARIOS"
                --nonblocking-scenarios "$SLOPE_NONBLOCKING_SCENARIOS"
                --min-r2 "$SLOPE_MIN_R2"
                --max-a-regression-pct "$SLOPE_MAX_A_REGRESSION_PCT"
                --max-b-regression-pct "$SLOPE_MAX_B_REGRESSION_PCT"
                --instability-r2-margin "$SLOPE_INSTABILITY_R2_MARGIN"
                --instability-a-overage-pct "$SLOPE_INSTABILITY_A_OVERAGE_PCT"
                --instability-b-overage-pct "$SLOPE_INSTABILITY_B_OVERAGE_PCT"
                --min-baseline-b-ns-for-gate "$SLOPE_MIN_BASELINE_B_NS_FOR_GATE"
                --runtime-measure-runs "$SLOPE_RUNTIME_MEASURE_RUNS"
                --runtime-trim-pct "$SLOPE_RUNTIME_TRIM_PCT"
                --baseline-fingerprint-file "$PERF_BASELINE_FINGERPRINT_FILE"
                --baseline-fingerprint-status "$PERF_BASELINE_FINGERPRINT_STATUS"
                --baseline-fingerprint-notes "$PERF_BASELINE_FINGERPRINT_NOTES"
                --cpu-model "$PERF_ENV_CPU_MODEL"
                --out-json "$shadow_json"
                --out-md "$shadow_md"
            )
        fi

        if [[ -n "$shadow_name" ]]; then
            if [[ -f "$OUT_DIR/slope_report.json" ]]; then
                slope_args_shadow+=(--input-report "$OUT_DIR/slope_report.json")
                echo "[perf] slope shadow replay source: $OUT_DIR/slope_report.json"
            else
                echo "[perf] WARN: slope shadow replay source missing; running live shadow measurement"
            fi
            if [[ "$SLOPE_REQUIRE_BASELINE" == "1" ]]; then
                slope_args_shadow+=(--require-baseline)
            fi
            if [[ "$ENABLE_FUSION_RULE_GATE" != "1" ]]; then
                slope_args_shadow+=(--disable-fusion-rule-gate)
            fi
            echo "[perf] Run ${shadow_name^} slope gate shadow (observe-only)"
            set +e
            "${slope_args_shadow[@]}"
            slope_shadow_rc=$?
            set -e
            if [[ "$slope_shadow_rc" -ne 0 ]]; then
                echo "[perf] WARN: ${shadow_name} slope gate shadow exited with rc=${slope_shadow_rc} (observe-only)"
            fi
        fi

        if [[ "$SLOPE_GATE_RUST_COMPARE" == "1" && -n "$shadow_json" && -f "$OUT_DIR/slope_report.json" && -f "$shadow_json" ]]; then
            shadow_compare_json="$OUT_DIR/slope_report_shadow_compare.json"
            shadow_compare_txt="$OUT_DIR/slope_report_shadow_compare.txt"
            set +e
            python3 "$SLOPE_SHADOW_COMPARE_SCRIPT" \
                --primary-json "$OUT_DIR/slope_report.json" \
                --shadow-json "$shadow_json" \
                --primary-impl "$primary_choice" \
                --shadow-impl "$shadow_name" \
                --out-json "$shadow_compare_json" \
                --out-text "$shadow_compare_txt"
            slope_cmp_rc=$?
            set -e
            if [[ -f "$shadow_compare_txt" ]]; then
                cp "$shadow_compare_txt" "$shadow_cmp_txt"
            fi
            if [[ "$slope_cmp_rc" -ne 0 ]]; then
                echo "[perf] WARN: slope shadow compare mismatch (observe-only)"
                cat "$shadow_compare_txt" || true
            fi
        fi
    fi
fi

if [[ "$ENABLE_SPEEDUP_GATE" == "1" ]]; then
    echo "[perf] Run runtime-only benchmarks"
    for i in "${!BENCH_NAMES[@]}"; do
        name="${BENCH_NAMES[$i]}"
        naux_file="$ROOT_DIR/${NAUX_FILES[$i]}"

        naux_out="$(${PIN[@]} "$ROOT_DIR/target/release/naux" dev benchrt "$naux_file" --engine="$ENGINE" --iters="$ITERS" --warmup-ms="$WARMUP_MS")"
        echo "$naux_out" > "$OUT_DIR/${name}.naux.log"
        naux_profile_json="$(${PIN[@]} env NAUX_TRACE_PROFILE=1 "$ROOT_DIR/target/release/naux" dev benchrt "$naux_file" --engine="$ENGINE" --iters="$ITERS" --warmup-ms="$WARMUP_MS" --json)"
        echo "$naux_profile_json" > "$OUT_DIR/${name}.naux.profile.json"

        c_out="$(${PIN[@]} "$OUT_DIR/bin/${C_BINS[$i]}" 100000 "$ITERS" "$WARMUP_MS" "$REPS")"
        echo "$c_out" > "$OUT_DIR/${name}.c.log"

        naux_median="$(parse_metric "median" "$naux_out")"
        naux_p95="$(parse_metric "p95" "$naux_out")"
        naux_hot_code_avg="$(parse_trace_hot_code_avg "$naux_out")"
        if [[ -z "$naux_hot_code_avg" ]]; then
            naux_hot_code_avg="0.0"
        fi
        c_median="$(parse_metric "median" "$c_out")"
        c_p95="$(parse_metric "p95" "$c_out")"
        runtime_calls="$(parse_json_int "total_runtime_calls" "$naux_profile_json")"
        branch_ratio="$(parse_json_float "branch_taken_ratio" "$naux_profile_json")"
        temp_list_elided="$(parse_json_int "total_runtime_temp_list_elided" "$naux_profile_json")"
        temp_map_elided="$(parse_json_int "total_runtime_temp_map_elided" "$naux_profile_json")"
        temp_list_materialized="$(parse_json_int "total_runtime_temp_list_materialized" "$naux_profile_json")"
        temp_map_materialized="$(parse_json_int "total_runtime_temp_map_materialized" "$naux_profile_json")"
        [[ -z "$runtime_calls" ]] && runtime_calls="0"
        [[ -z "$branch_ratio" ]] && branch_ratio="0.0"
        [[ -z "$temp_list_elided" ]] && temp_list_elided="0"
        [[ -z "$temp_map_elided" ]] && temp_map_elided="0"
        [[ -z "$temp_list_materialized" ]] && temp_list_materialized="0"
        [[ -z "$temp_map_materialized" ]] && temp_map_materialized="0"
        temp_list_materialized_ratio_pct="$(calc_ratio_pct "$temp_list_materialized" "$temp_list_elided")"
        temp_map_materialized_ratio_pct="$(calc_ratio_pct "$temp_map_materialized" "$temp_map_elided")"

        if [[ -z "$naux_median" || -z "$naux_p95" || -z "$c_median" || -z "$c_p95" ]]; then
            echo "[perf] Failed to parse benchmark output for $name" >&2
            FAILED=1
            continue
        fi

        sp="$(speedup "$c_median" "$naux_median")"
        required_speedup="$(min_speedup_for "$name")"
        ok="$(ge_float "$sp" "$required_speedup")"
        if [[ "$ok" != "1" ]]; then
            FAILED=1
            echo "::error::speedup gate failed for $name (got ${sp}x, required >= ${required_speedup}x)"
        fi

        hard_limit="$(hard_limit_for "$name")"
        hard_ok="1"
        if [[ "$hard_limit" != "0" ]]; then
            if [[ "$(gt_float "$naux_hot_code_avg" "$hard_limit")" == "1" || "$(ge_float "0" "$naux_hot_code_avg")" == "1" ]]; then
                hard_ok="0"
                FAILED=1
                echo "::error::hard hot-path code-size limit exceeded for $name (avg=${naux_hot_code_avg}B, limit=${hard_limit}B)"
            fi
        fi

        baseline_code="$(baseline_code_for "$name" "$PERF_BASELINE_TSV")"
        soft_warn="0"
        soft_threshold="0.000"
        if [[ -n "${baseline_code:-}" ]]; then
            factor="$(awk -v p="$SOFT_REGRESSION_PCT" 'BEGIN { printf "%.6f", 1.0 + (p / 100.0) }')"
            soft_threshold="$(mul_float "$baseline_code" "$factor")"
            if [[ "$(gt_float "$naux_hot_code_avg" "$soft_threshold")" == "1" ]]; then
                soft_warn="1"
                echo "::warning::hot-path code-size regression for $name (avg=${naux_hot_code_avg}B, baseline=${baseline_code}B, threshold=${soft_threshold}B)"
                if [[ "$SOFT_REGRESSION_FAIL" == "1" ]]; then
                    FAILED=1
                fi
            fi
        fi

        runtime_calls_ok="1"
        if [[ "$REQUIRE_ZERO_RUNTIME_CALLS_MATH" == "1" ]]; then
            case "$name" in
                sum_dense|dot_product)
                    if [[ "$runtime_calls" != "0" ]]; then
                        runtime_calls_ok="0"
                        FAILED=1
                        echo "::error::runtime call count must be 0 for $name (got $runtime_calls)"
                    fi
                    ;;
            esac
        fi

        printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
            "$name" "$naux_median" "$naux_p95" "$c_median" "$c_p95" "$sp" "$required_speedup" \
            "$naux_hot_code_avg" "$hard_limit" "$hard_ok" "${baseline_code:-}" "$soft_warn" \
            "$runtime_calls" "$runtime_calls_ok" "$branch_ratio" \
            "$temp_list_elided" "$temp_map_elided" "$temp_list_materialized" "$temp_map_materialized" \
            "$temp_list_materialized_ratio_pct" "$temp_map_materialized_ratio_pct" >> "$TSV"
    done
else
    echo "[perf] Skip runtime-only benchmarks (ENABLE_SPEEDUP_GATE=0)"
fi

{
    echo "# Performance Contract Report"
    echo
    echo "- engine: $ENGINE"
    echo "- iters: $ITERS"
    echo "- warmup_ms: $WARMUP_MS"
    echo "- reps(C): $REPS"
    echo "- min_speedup_required_default: $MIN_SPEEDUP"
    echo "- min_speedup_required_sum_dense: ${MIN_SPEEDUP_SUM_DENSE:-$MIN_SPEEDUP}"
    echo "- min_speedup_required_list_update: ${MIN_SPEEDUP_LIST_UPDATE:-$MIN_SPEEDUP}"
    echo "- min_speedup_required_dot_product: ${MIN_SPEEDUP_DOT_PRODUCT:-$MIN_SPEEDUP}"
    echo "- hard_limit_math_bytes: $HARD_LIMIT_MATH_BYTES"
    echo "- hard_limit_default_bytes: $HARD_LIMIT_DEFAULT_BYTES"
    echo "- soft_regression_pct: $SOFT_REGRESSION_PCT"
    echo "- require_zero_runtime_calls_math: $REQUIRE_ZERO_RUNTIME_CALLS_MATH"
    echo "- require_patch_commits_bimorphic: $REQUIRE_PATCH_COMMITS_BIMORPHIC"
    echo "- require_max_revert_streak_bimorphic: $REQUIRE_MAX_REVERT_STREAK_BIMORPHIC"
    echo "- max_revert_streak_bimorphic: $MAX_REVERT_STREAK_BIMORPHIC"
    echo "- require_temp_alloc_metrics: $REQUIRE_TEMP_ALLOC_METRICS"
    echo "- temp_alloc_bench_file: $TEMP_ALLOC_BENCH_FILE"
    echo "- min_temp_list_elided: $MIN_TEMP_LIST_ELIDED"
    echo "- min_temp_map_elided: $MIN_TEMP_MAP_ELIDED"
    echo "- max_temp_list_materialized: $MAX_TEMP_LIST_MATERIALIZED"
    echo "- max_temp_map_materialized: $MAX_TEMP_MAP_MATERIALIZED"
    echo "- max_temp_list_materialized_ratio_pct: $MAX_TEMP_LIST_MATERIALIZED_RATIO_PCT"
    echo "- max_temp_map_materialized_ratio_pct: $MAX_TEMP_MAP_MATERIALIZED_RATIO_PCT"
    echo "- require_temp_map_alloc_metrics: $REQUIRE_TEMP_MAP_ALLOC_METRICS"
    echo "- temp_map_alloc_bench_file: $TEMP_MAP_ALLOC_BENCH_FILE"
    echo "- min_temp_map_bench_elided: $MIN_TEMP_MAP_BENCH_ELIDED"
    echo "- max_temp_map_bench_materialized: $MAX_TEMP_MAP_BENCH_MATERIALIZED"
    echo "- max_temp_map_bench_materialized_ratio_pct: $MAX_TEMP_MAP_BENCH_MATERIALIZED_RATIO_PCT"
    echo "- enable_slope_gate: $ENABLE_SLOPE_GATE"
    echo "- slope_baseline_file: $SLOPE_BASELINE_TSV"
    echo "- fusion_expectations_file: $FUSION_EXPECTATIONS_FILE"
    echo "- fusion_expectation_scenarios: $FUSION_EXPECTATION_SCENARIOS"
    echo "- slope_nonblocking_scenarios: $SLOPE_NONBLOCKING_SCENARIOS"
    echo "- slope_min_r2: $SLOPE_MIN_R2"
    echo "- slope_max_a_regression_pct: $SLOPE_MAX_A_REGRESSION_PCT"
    echo "- slope_max_b_regression_pct: $SLOPE_MAX_B_REGRESSION_PCT"
    echo "- slope_instability_r2_margin: $SLOPE_INSTABILITY_R2_MARGIN"
    echo "- slope_instability_a_overage_pct: $SLOPE_INSTABILITY_A_OVERAGE_PCT"
    echo "- slope_instability_b_overage_pct: $SLOPE_INSTABILITY_B_OVERAGE_PCT"
    echo "- slope_min_baseline_b_ns_for_gate: $SLOPE_MIN_BASELINE_B_NS_FOR_GATE"
    echo "- slope_require_baseline: $SLOPE_REQUIRE_BASELINE"
    echo "- slope_default_iters: $SLOPE_DEFAULT_ITERS"
    echo "- slope_default_warmup_ms: $SLOPE_DEFAULT_WARMUP_MS"
    echo "- slope_dot_runtime_iters: $SLOPE_DOT_RUNTIME_ITERS"
    echo "- slope_dot_runtime_warmup_ms: $SLOPE_DOT_RUNTIME_WARMUP_MS"
    echo "- slope_dot_trace_iters: $SLOPE_DOT_TRACE_ITERS"
    echo "- slope_dot_trace_warmup_ms: $SLOPE_DOT_TRACE_WARMUP_MS"
    echo "- slope_map_runtime_iters: $SLOPE_MAP_RUNTIME_ITERS"
    echo "- slope_map_runtime_warmup_ms: $SLOPE_MAP_RUNTIME_WARMUP_MS"
    echo "- slope_map_guard_entry_iters: $SLOPE_MAP_GUARD_ENTRY_ITERS"
    echo "- slope_map_guard_entry_warmup_ms: $SLOPE_MAP_GUARD_ENTRY_WARMUP_MS"
    echo "- slope_map_get_mul_acc_iters: $SLOPE_MAP_GET_MUL_ACC_ITERS"
    echo "- slope_map_get_mul_acc_warmup_ms: $SLOPE_MAP_GET_MUL_ACC_WARMUP_MS"
    echo "- slope_map_get_cmp_branch_iters: $SLOPE_MAP_GET_CMP_BRANCH_ITERS"
    echo "- slope_map_get_cmp_branch_warmup_ms: $SLOPE_MAP_GET_CMP_BRANCH_WARMUP_MS"
    echo "- slope_sacrificial_warmup_file: $SLOPE_SACRIFICIAL_WARMUP_FILE"
    echo "- slope_sacrificial_warmup_n: $SLOPE_SACRIFICIAL_WARMUP_N"
    echo "- slope_sacrificial_warmup_iters: $SLOPE_SACRIFICIAL_WARMUP_ITERS"
    echo "- slope_sacrificial_warmup_warmup_ms: $SLOPE_SACRIFICIAL_WARMUP_WARMUP_MS"
    echo "- slope_sacrificial_warmup_settle_ms: $SLOPE_SACRIFICIAL_WARMUP_SETTLE_MS"
    echo "- slope_runtime_measure_runs: $SLOPE_RUNTIME_MEASURE_RUNS"
    echo "- slope_runtime_trim_pct: $SLOPE_RUNTIME_TRIM_PCT"
    echo "- slope_gate_max_attempts: $SLOPE_GATE_MAX_ATTEMPTS"
    echo "- slope_retryable_final_enforce: $SLOPE_RETRYABLE_FINAL_ENFORCE"
    echo "- slope_gate_primary: $SLOPE_GATE_PRIMARY"
    echo "- slope_gate_primary_fallback_py: $SLOPE_GATE_PRIMARY_FALLBACK_PY"
    echo "- enable_slope_gate_rust_shadow: $ENABLE_SLOPE_GATE_RUST_SHADOW"
    echo "- slope_gate_rust_shadow_ready: $SLOPE_GATE_RUST_SHADOW_READY"
    echo "- need_rust_slope_gate: $NEED_RUST_SLOPE_GATE"
    echo "- slope_gate_rust_bin: $SLOPE_GATE_RUST_BIN"
    echo "- slope_gate_rust_compare: $SLOPE_GATE_RUST_COMPARE"
    echo "- enable_fusion_rule_gate: $ENABLE_FUSION_RULE_GATE"
    echo "- enable_fixed_cost_gate: $ENABLE_FIXED_COST_GATE"
    echo "- fixed_cost_low_n_baseline_file: $FIXED_COST_LOW_N_BASELINE_TSV"
    echo "- fixed_cost_cold_baseline_file: $FIXED_COST_COLD_BASELINE_TSV"
    echo "- fixed_cost_low_n_values: $FIXED_COST_LOW_N_VALUES"
    echo "- fixed_cost_low_n_iters: $FIXED_COST_LOW_N_ITERS"
    echo "- fixed_cost_low_n_warmup_ms: $FIXED_COST_LOW_N_WARMUP_MS"
    echo "- fixed_cost_low_n_discard_runs: $FIXED_COST_LOW_N_DISCARD_RUNS"
    echo "- fixed_cost_low_n_measure_runs: $FIXED_COST_LOW_N_MEASURE_RUNS"
    echo "- fixed_cost_low_n_trim_pct: $FIXED_COST_LOW_N_TRIM_PCT"
    echo "- fixed_cost_low_n_cooldown_ms: $FIXED_COST_LOW_N_COOLDOWN_MS"
    echo "- fixed_cost_low_n_max_reg_pct: $FIXED_COST_LOW_N_MAX_REG_PCT"
    echo "- fixed_cost_low_n_abs_ns: $FIXED_COST_LOW_N_ABS_NS"
    echo "- fixed_cost_low_n_abs_ns_tiny: $FIXED_COST_LOW_N_ABS_NS_TINY"
    echo "- fixed_cost_low_n_tiny_threshold: $FIXED_COST_LOW_N_TINY_THRESHOLD"
    echo "- fixed_cost_cold_n: $FIXED_COST_COLD_N"
    echo "- fixed_cost_cold_samples: $FIXED_COST_COLD_SAMPLES"
    echo "- fixed_cost_cold_max_reg_pct: $FIXED_COST_COLD_MAX_REG_PCT"
    echo "- fixed_cost_cold_abs_ns: $FIXED_COST_COLD_ABS_NS"
    echo "- fixed_cost_instability_overage_pct: $FIXED_COST_INSTABILITY_OVERAGE_PCT"
    echo "- fixed_cost_instability_overage_ns: $FIXED_COST_INSTABILITY_OVERAGE_NS"
    echo "- fixed_cost_gate_max_attempts: $FIXED_COST_GATE_MAX_ATTEMPTS"
    echo "- fixed_cost_pre_cooldown_ms: $FIXED_COST_PRE_COOLDOWN_MS"
    echo "- slope_pre_cooldown_ms: $SLOPE_PRE_COOLDOWN_MS"
    echo "- enable_perf_stat_capture: $ENABLE_PERF_STAT_CAPTURE"
    echo "- perf_stat_n: $PERF_STAT_N"
    echo "- perf_stat_iters: $PERF_STAT_ITERS"
    echo "- perf_stat_warmup_ms: $PERF_STAT_WARMUP_MS"
    echo "- enable_speedup_gate: $ENABLE_SPEEDUP_GATE"
    echo "- enable_deopt_report: $ENABLE_DEOPT_REPORT"
    echo "- enable_deopt_warn_gate: $ENABLE_DEOPT_WARN_GATE"
    echo "- deopt_warn_enforce: $DEOPT_WARN_ENFORCE"
    echo "- deopt_warn_max_summary_deopt_rate_pct: $DEOPT_WARN_MAX_SUMMARY_DEOPT_RATE_PCT"
    echo "- deopt_warn_max_summary_guard_fail_rate_pct: $DEOPT_WARN_MAX_SUMMARY_GUARD_FAIL_RATE_PCT"
    echo "- deopt_warn_max_total_clones: $DEOPT_WARN_MAX_TOTAL_CLONES"
    echo "- deopt_warn_max_scenario_clones: $DEOPT_WARN_MAX_SCENARIO_CLONES"
    echo "- deopt_warn_max_unknown_deopt_reasons: $DEOPT_WARN_MAX_UNKNOWN_DEOPT_REASONS"
    echo "- deopt_warn_max_unknown_guard_reasons: $DEOPT_WARN_MAX_UNKNOWN_GUARD_REASONS"
    echo "- deopt_warn_min_total_hits_for_rate_checks: $DEOPT_WARN_MIN_TOTAL_HITS_FOR_RATE_CHECKS"
    echo "- enable_clippy_gate: $ENABLE_CLIPPY_GATE"
    echo "- clippy_package: ${CLIPPY_PACKAGE:-<workspace>}"
    echo "- clippy_all_targets: $CLIPPY_ALL_TARGETS"
    echo "- clippy_all_features: $CLIPPY_ALL_FEATURES"
    echo "- clippy_deny_warnings: $CLIPPY_DENY_WARNINGS"
    echo "- enable_microarch_observe: $ENABLE_MICROARCH_OBSERVE"
    echo "- perf_env_enforce: $PERF_ENV_ENFORCE"
    echo "- perf_expect_governor: ${PERF_EXPECT_GOVERNOR:-<unset>}"
    echo "- perf_expect_intel_no_turbo: ${PERF_EXPECT_INTEL_NO_TURBO:-<unset>}"
    echo "- perf_expect_amd_boost: ${PERF_EXPECT_AMD_BOOST:-<unset>}"
    echo "- perf_require_taskset: $PERF_REQUIRE_TASKSET"
    echo "- perf_env_status: $PERF_ENV_STATUS"
    echo "- perf_env_governor_actual: $PERF_ENV_GOVERNOR_ACTUAL"
    echo "- perf_env_turbo_source: $PERF_ENV_TURBO_SOURCE"
    echo "- perf_env_turbo_actual: $PERF_ENV_TURBO_ACTUAL"
    echo "- perf_env_cpu_model: $PERF_ENV_CPU_MODEL"
    echo "- perf_env_notes: ${PERF_ENV_NOTES:-none}"
    echo "- baseline_fingerprint_file: $PERF_BASELINE_FINGERPRINT_FILE"
    echo "- baseline_fingerprint_require: $PERF_BASELINE_FINGERPRINT_REQUIRE"
    echo "- baseline_fingerprint_enforce: $PERF_BASELINE_FINGERPRINT_ENFORCE"
    echo "- baseline_fingerprint_write_current: $PERF_BASELINE_FINGERPRINT_WRITE_CURRENT"
    echo "- baseline_fingerprint_status: $PERF_BASELINE_FINGERPRINT_STATUS"
    echo "- baseline_fingerprint_notes: ${PERF_BASELINE_FINGERPRINT_NOTES:-none}"
    echo "- patch_commit_bench_file: $PATCH_COMMIT_BENCH_FILE"
    echo "- baseline_file: $PERF_BASELINE_TSV"
    echo "- code_size_metric: hot_path_bytes"
    if [[ ${#PIN[@]} -gt 0 ]]; then
        echo "- cpu_pin: taskset -c $CPU_CORE"
    else
        echo "- cpu_pin: disabled (taskset not found)"
    fi
    echo
    echo "| benchmark | naux median ns/op | naux p95 ns/op | c median ns/op | c p95 ns/op | speedup (C/NAUX) | required speedup | hot-path code avg bytes | hard limit bytes | hard ok | baseline bytes | soft warn | runtime calls | runtime calls ok | branch taken ratio | temp list elided | temp map elided | temp list materialized | temp map materialized | temp list materialized ratio % | temp map materialized ratio % |"
    echo "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    while IFS=$'\t' read -r name naux_med naux_p95 c_med c_p95 sp required_sp code_avg hard_limit hard_ok baseline_code soft_warn runtime_calls runtime_calls_ok branch_ratio temp_list_elided temp_map_elided temp_list_materialized temp_map_materialized temp_list_materialized_ratio_pct temp_map_materialized_ratio_pct; do
        [[ -z "$name" ]] && continue
        echo "| $name | $naux_med | $naux_p95 | $c_med | $c_p95 | $sp | $required_sp | $code_avg | ${hard_limit:-0} | $hard_ok | ${baseline_code:-} | $soft_warn | $runtime_calls | $runtime_calls_ok | $branch_ratio | ${temp_list_elided:-0} | ${temp_map_elided:-0} | ${temp_list_materialized:-0} | ${temp_map_materialized:-0} | ${temp_list_materialized_ratio_pct:-0.0000} | ${temp_map_materialized_ratio_pct:-0.0000} |"
    done < "$TSV"
} > "$MD"

if [[ "$REQUIRE_PATCH_COMMITS_BIMORPHIC" == "1" || "$REQUIRE_MAX_REVERT_STREAK_BIMORPHIC" == "1" ]]; then
    echo "[perf] Check adaptive patch metrics on bimorphic benchmark"
    patch_json="$(${PIN[@]} env NAUX_TRACE_PROFILE=1 "$ROOT_DIR/target/release/naux" dev benchrt "$ROOT_DIR/$PATCH_COMMIT_BENCH_FILE" --engine="$ENGINE" --iters="$ITERS" --warmup-ms="$WARMUP_MS" --json)"
    echo "$patch_json" > "$OUT_DIR/patch_commits_check.json"
    if [[ "$REQUIRE_PATCH_COMMITS_BIMORPHIC" == "1" ]]; then
        patch_commits="$(parse_json_int "total_patch_commits" "$patch_json")"
        [[ -z "$patch_commits" ]] && patch_commits="0"
        if [[ "$patch_commits" == "0" ]]; then
            echo "::error::adaptive patch commits must be > 0 for $PATCH_COMMIT_BENCH_FILE"
            FAILED=1
        fi
    fi
    if [[ "$REQUIRE_MAX_REVERT_STREAK_BIMORPHIC" == "1" ]]; then
        max_revert_streak="$(parse_json_int "max_revert_streak" "$patch_json")"
        [[ -z "$max_revert_streak" ]] && max_revert_streak="0"
        if (( max_revert_streak > MAX_REVERT_STREAK_BIMORPHIC )); then
            echo "::error::max_revert_streak must be <= $MAX_REVERT_STREAK_BIMORPHIC for $PATCH_COMMIT_BENCH_FILE (got $max_revert_streak)"
            FAILED=1
        fi
    fi
fi

if [[ "$REQUIRE_TEMP_ALLOC_METRICS" == "1" ]]; then
    echo "[perf] Check escape-analysis temp alloc metrics"
    temp_json="$(${PIN[@]} env NAUX_TRACE_PROFILE=1 "$ROOT_DIR/target/release/naux" dev benchrt "$ROOT_DIR/$TEMP_ALLOC_BENCH_FILE" --engine="$ENGINE" --iters="$ITERS" --warmup-ms="$WARMUP_MS" --json)"
    echo "$temp_json" > "$OUT_DIR/temp_alloc_check.json"
    temp_list_elided="$(parse_json_int "total_runtime_temp_list_elided" "$temp_json")"
    temp_map_elided="$(parse_json_int "total_runtime_temp_map_elided" "$temp_json")"
    temp_list_materialized="$(parse_json_int "total_runtime_temp_list_materialized" "$temp_json")"
    temp_map_materialized="$(parse_json_int "total_runtime_temp_map_materialized" "$temp_json")"
    [[ -z "$temp_list_elided" ]] && temp_list_elided="0"
    [[ -z "$temp_map_elided" ]] && temp_map_elided="0"
    [[ -z "$temp_list_materialized" ]] && temp_list_materialized="0"
    [[ -z "$temp_map_materialized" ]] && temp_map_materialized="0"

    if (( temp_list_elided < MIN_TEMP_LIST_ELIDED )); then
        echo "::error::temp list elided must be >= $MIN_TEMP_LIST_ELIDED for $TEMP_ALLOC_BENCH_FILE (got $temp_list_elided)"
        FAILED=1
    fi
    if (( temp_map_elided < MIN_TEMP_MAP_ELIDED )); then
        echo "::error::temp map elided must be >= $MIN_TEMP_MAP_ELIDED for $TEMP_ALLOC_BENCH_FILE (got $temp_map_elided)"
        FAILED=1
    fi
    if (( temp_list_materialized > MAX_TEMP_LIST_MATERIALIZED )); then
        echo "::error::temp list materialized must be <= $MAX_TEMP_LIST_MATERIALIZED for $TEMP_ALLOC_BENCH_FILE (got $temp_list_materialized)"
        FAILED=1
    fi
    if (( temp_map_materialized > MAX_TEMP_MAP_MATERIALIZED )); then
        echo "::error::temp map materialized must be <= $MAX_TEMP_MAP_MATERIALIZED for $TEMP_ALLOC_BENCH_FILE (got $temp_map_materialized)"
        FAILED=1
    fi
    temp_list_materialized_ratio_pct="$(calc_ratio_pct "$temp_list_materialized" "$temp_list_elided")"
    temp_map_materialized_ratio_pct="$(calc_ratio_pct "$temp_map_materialized" "$temp_map_elided")"
    if [[ "$(gt_float "$temp_list_materialized_ratio_pct" "$MAX_TEMP_LIST_MATERIALIZED_RATIO_PCT")" == "1" ]]; then
        echo "::error::temp list materialized ratio must be <= $MAX_TEMP_LIST_MATERIALIZED_RATIO_PCT% for $TEMP_ALLOC_BENCH_FILE (got ${temp_list_materialized_ratio_pct}%)"
        FAILED=1
    fi
    if [[ "$(gt_float "$temp_map_materialized_ratio_pct" "$MAX_TEMP_MAP_MATERIALIZED_RATIO_PCT")" == "1" ]]; then
        echo "::error::temp map materialized ratio must be <= $MAX_TEMP_MAP_MATERIALIZED_RATIO_PCT% for $TEMP_ALLOC_BENCH_FILE (got ${temp_map_materialized_ratio_pct}%)"
        FAILED=1
    fi
fi

if [[ "$REQUIRE_TEMP_MAP_ALLOC_METRICS" == "1" ]]; then
    echo "[perf] Check escape-analysis map temp alloc metrics"
    temp_map_json="$(${PIN[@]} env NAUX_TRACE_PROFILE=1 "$ROOT_DIR/target/release/naux" dev benchrt "$ROOT_DIR/$TEMP_MAP_ALLOC_BENCH_FILE" --engine="$ENGINE" --iters="$ITERS" --warmup-ms="$WARMUP_MS" --json)"
    echo "$temp_map_json" > "$OUT_DIR/temp_map_alloc_check.json"
    temp_map_elided_bench="$(parse_json_int "total_runtime_temp_map_elided" "$temp_map_json")"
    temp_map_materialized_bench="$(parse_json_int "total_runtime_temp_map_materialized" "$temp_map_json")"
    [[ -z "$temp_map_elided_bench" ]] && temp_map_elided_bench="0"
    [[ -z "$temp_map_materialized_bench" ]] && temp_map_materialized_bench="0"

    if (( temp_map_elided_bench < MIN_TEMP_MAP_BENCH_ELIDED )); then
        echo "::error::temp map elided must be >= $MIN_TEMP_MAP_BENCH_ELIDED for $TEMP_MAP_ALLOC_BENCH_FILE (got $temp_map_elided_bench)"
        FAILED=1
    fi
    if (( temp_map_materialized_bench > MAX_TEMP_MAP_BENCH_MATERIALIZED )); then
        echo "::error::temp map materialized must be <= $MAX_TEMP_MAP_BENCH_MATERIALIZED for $TEMP_MAP_ALLOC_BENCH_FILE (got $temp_map_materialized_bench)"
        FAILED=1
    fi
    temp_map_materialized_ratio_pct_bench="$(calc_ratio_pct "$temp_map_materialized_bench" "$temp_map_elided_bench")"
    if [[ "$(gt_float "$temp_map_materialized_ratio_pct_bench" "$MAX_TEMP_MAP_BENCH_MATERIALIZED_RATIO_PCT")" == "1" ]]; then
        echo "::error::temp map materialized ratio must be <= $MAX_TEMP_MAP_BENCH_MATERIALIZED_RATIO_PCT% for $TEMP_MAP_ALLOC_BENCH_FILE (got ${temp_map_materialized_ratio_pct_bench}%)"
        FAILED=1
    fi
fi

PERF_ENV_NOTES_JSON="$(json_escape "${PERF_ENV_NOTES:-}")"
PERF_ENV_CPU_MODEL_JSON="$(json_escape "${PERF_ENV_CPU_MODEL:-}")"
PERF_BASELINE_FINGERPRINT_FILE_JSON="$(json_escape "${PERF_BASELINE_FINGERPRINT_FILE:-}")"
PERF_BASELINE_FINGERPRINT_STATUS_JSON="$(json_escape "${PERF_BASELINE_FINGERPRINT_STATUS:-}")"
PERF_BASELINE_FINGERPRINT_NOTES_JSON="$(json_escape "${PERF_BASELINE_FINGERPRINT_NOTES:-}")"
PERF_GIT_SHA="$(git rev-parse HEAD 2>/dev/null || true)"
PERF_GIT_BRANCH="${GITHUB_REF_NAME:-}"
if [[ -z "$PERF_GIT_BRANCH" ]]; then
    PERF_GIT_BRANCH="$(git branch --show-current 2>/dev/null || true)"
fi
PERF_GIT_DIRTY=false
if [[ -n "$(git status --porcelain 2>/dev/null || true)" ]]; then
    PERF_GIT_DIRTY=true
fi
PERF_GIT_SHA_JSON="$(json_escape "$PERF_GIT_SHA")"
PERF_GIT_BRANCH_JSON="$(json_escape "$PERF_GIT_BRANCH")"
PERF_CI_RUN_ID_JSON="$(json_escape "${GITHUB_RUN_ID:-}")"
PERF_CI_RUN_ATTEMPT_JSON="$(json_escape "${GITHUB_RUN_ATTEMPT:-}")"
SLOPE_GATE_PRIMARY_ACTUAL="${primary_choice:-disabled}"
SLOPE_GATE_PRIMARY_FALLBACK_USED=false
if [[ "$ENABLE_SLOPE_GATE" == "1" && "$SLOPE_GATE_PRIMARY_ACTUAL" != "$SLOPE_GATE_PRIMARY" ]]; then
    SLOPE_GATE_PRIMARY_FALLBACK_USED=true
fi

{
    echo "{"
    echo "  \"meta\": {"
    echo "    \"engine\": \"$ENGINE\"," 
    echo "    \"iters\": $ITERS,"
    echo "    \"warmup_ms\": $WARMUP_MS,"
    echo "    \"reps\": $REPS,"
    echo "    \"min_speedup_required_default\": $MIN_SPEEDUP,"
    echo "    \"min_speedup_required_sum_dense\": ${MIN_SPEEDUP_SUM_DENSE:-$MIN_SPEEDUP},"
    echo "    \"min_speedup_required_list_update\": ${MIN_SPEEDUP_LIST_UPDATE:-$MIN_SPEEDUP},"
    echo "    \"min_speedup_required_dot_product\": ${MIN_SPEEDUP_DOT_PRODUCT:-$MIN_SPEEDUP},"
    echo "    \"hard_limit_math_bytes\": $HARD_LIMIT_MATH_BYTES,"
    echo "    \"hard_limit_default_bytes\": $HARD_LIMIT_DEFAULT_BYTES,"
    echo "    \"soft_regression_pct\": $SOFT_REGRESSION_PCT,"
    echo "    \"require_patch_commits_bimorphic\": $REQUIRE_PATCH_COMMITS_BIMORPHIC,"
    echo "    \"require_max_revert_streak_bimorphic\": $REQUIRE_MAX_REVERT_STREAK_BIMORPHIC,"
    echo "    \"max_revert_streak_bimorphic\": $MAX_REVERT_STREAK_BIMORPHIC,"
    echo "    \"require_temp_alloc_metrics\": $REQUIRE_TEMP_ALLOC_METRICS,"
    echo "    \"temp_alloc_bench_file\": \"$TEMP_ALLOC_BENCH_FILE\","
    echo "    \"min_temp_list_elided\": $MIN_TEMP_LIST_ELIDED,"
    echo "    \"min_temp_map_elided\": $MIN_TEMP_MAP_ELIDED,"
    echo "    \"max_temp_list_materialized\": $MAX_TEMP_LIST_MATERIALIZED,"
    echo "    \"max_temp_map_materialized\": $MAX_TEMP_MAP_MATERIALIZED,"
    echo "    \"max_temp_list_materialized_ratio_pct\": $MAX_TEMP_LIST_MATERIALIZED_RATIO_PCT,"
    echo "    \"max_temp_map_materialized_ratio_pct\": $MAX_TEMP_MAP_MATERIALIZED_RATIO_PCT,"
    echo "    \"require_temp_map_alloc_metrics\": $REQUIRE_TEMP_MAP_ALLOC_METRICS,"
    echo "    \"temp_map_alloc_bench_file\": \"$TEMP_MAP_ALLOC_BENCH_FILE\","
    echo "    \"min_temp_map_bench_elided\": $MIN_TEMP_MAP_BENCH_ELIDED,"
    echo "    \"max_temp_map_bench_materialized\": $MAX_TEMP_MAP_BENCH_MATERIALIZED,"
    echo "    \"max_temp_map_bench_materialized_ratio_pct\": $MAX_TEMP_MAP_BENCH_MATERIALIZED_RATIO_PCT,"
    echo "    \"enable_speedup_gate\": $ENABLE_SPEEDUP_GATE,"
    echo "    \"perf_env_enforce\": $PERF_ENV_ENFORCE,"
    echo "    \"perf_expect_governor\": \"$PERF_EXPECT_GOVERNOR\","
    echo "    \"perf_expect_intel_no_turbo\": \"$PERF_EXPECT_INTEL_NO_TURBO\","
    echo "    \"perf_expect_amd_boost\": \"$PERF_EXPECT_AMD_BOOST\","
    echo "    \"perf_require_taskset\": $PERF_REQUIRE_TASKSET,"
    echo "    \"perf_env_status\": \"$PERF_ENV_STATUS\","
    echo "    \"perf_env_governor_actual\": \"$PERF_ENV_GOVERNOR_ACTUAL\","
    echo "    \"perf_env_turbo_source\": \"$PERF_ENV_TURBO_SOURCE\","
    echo "    \"perf_env_turbo_actual\": \"$PERF_ENV_TURBO_ACTUAL\","
    echo "    \"perf_env_cpu_model\": \"$PERF_ENV_CPU_MODEL_JSON\","
    echo "    \"perf_env_notes\": \"$PERF_ENV_NOTES_JSON\","
    echo "    \"git_sha\": \"$PERF_GIT_SHA_JSON\","
    echo "    \"git_branch\": \"$PERF_GIT_BRANCH_JSON\","
    echo "    \"git_dirty\": $PERF_GIT_DIRTY,"
    echo "    \"ci_run_id\": \"$PERF_CI_RUN_ID_JSON\","
    echo "    \"ci_run_attempt\": \"$PERF_CI_RUN_ATTEMPT_JSON\","
    echo "    \"controlled_branch\": $PERF_CONTROLLED_BRANCH,"
    echo "    \"slope_gate_primary_requested\": \"$SLOPE_GATE_PRIMARY\","
    echo "    \"slope_gate_primary_actual\": \"$SLOPE_GATE_PRIMARY_ACTUAL\","
    echo "    \"slope_gate_primary_fallback_used\": $SLOPE_GATE_PRIMARY_FALLBACK_USED,"
    echo "    \"baseline_fingerprint_file\": \"$PERF_BASELINE_FINGERPRINT_FILE_JSON\","
    echo "    \"baseline_fingerprint_require\": $PERF_BASELINE_FINGERPRINT_REQUIRE,"
    echo "    \"baseline_fingerprint_enforce\": $PERF_BASELINE_FINGERPRINT_ENFORCE,"
    echo "    \"baseline_fingerprint_write_current\": $PERF_BASELINE_FINGERPRINT_WRITE_CURRENT,"
    echo "    \"baseline_fingerprint_status\": \"$PERF_BASELINE_FINGERPRINT_STATUS_JSON\","
    echo "    \"baseline_fingerprint_notes\": \"$PERF_BASELINE_FINGERPRINT_NOTES_JSON\","
    echo "    \"baseline_file\": \"$PERF_BASELINE_TSV\","
    echo "    \"code_size_metric\": \"hot_path_bytes\""
    echo "  },"
    echo "  \"results\": ["
    first=1
    while IFS=$'\t' read -r name naux_med naux_p95 c_med c_p95 sp required_sp code_avg hard_limit hard_ok baseline_code soft_warn runtime_calls runtime_calls_ok branch_ratio temp_list_elided temp_map_elided temp_list_materialized temp_map_materialized temp_list_materialized_ratio_pct temp_map_materialized_ratio_pct; do
        [[ -z "$name" ]] && continue
        if [[ "$first" -eq 0 ]]; then
            echo ","
        fi
        first=0
        cat <<ROW
    {
      "benchmark": "$name",
      "naux_median_ns": $naux_med,
      "naux_p95_ns": $naux_p95,
      "c_median_ns": $c_med,
      "c_p95_ns": $c_p95,
      "speedup_c_over_naux": $sp,
      "required_speedup_c_over_naux": $required_sp,
      "trace_code_avg_bytes": $code_avg,
      "hot_path_code_avg_bytes": $code_avg,
      "hard_limit_bytes": ${hard_limit:-0},
      "hard_limit_ok": $hard_ok,
      "baseline_trace_code_bytes": ${baseline_code:-null},
      "soft_regression_warn": $soft_warn,
      "runtime_calls": ${runtime_calls:-0},
      "runtime_calls_ok": ${runtime_calls_ok:-1},
      "branch_taken_ratio": ${branch_ratio:-0},
      "temp_list_elided": ${temp_list_elided:-0},
      "temp_map_elided": ${temp_map_elided:-0},
      "temp_list_materialized": ${temp_list_materialized:-0},
      "temp_map_materialized": ${temp_map_materialized:-0},
      "temp_list_materialized_ratio_pct": ${temp_list_materialized_ratio_pct:-0},
      "temp_map_materialized_ratio_pct": ${temp_map_materialized_ratio_pct:-0}
    }
ROW
    done < "$TSV"
    echo "  ]"
    echo "}"
} > "$JSON"

cat "$MD"


if [[ "$ENABLE_DEOPT_REPORT" == "1" ]]; then
    echo "[perf] Render deopt telemetry artifacts"
    set +e
    python3 "$DEOPT_REPORT_SCRIPT" \
        --profiles-root "$OUT_DIR" \
        --slope-report "$OUT_DIR/slope_report.json" \
        --fixed-cost-report "$OUT_DIR/fixed_cost_report.json" \
        --out-json "$OUT_DIR/deopt_report.json" \
        --out-md "$OUT_DIR/deopt_report.md"
    deopt_rc=$?
    set -e
    if [[ "$deopt_rc" -ne 0 ]]; then
        echo "[perf] WARN: deopt artifact render failed (rc=${deopt_rc})"
    fi
fi

if [[ "$ENABLE_DEOPT_WARN_GATE" == "1" ]]; then
    echo "[perf] Evaluate deopt warn gate"
    deopt_warn_args=(
        "$DEOPT_WARN_GATE_SCRIPT"
        --deopt-report "$OUT_DIR/deopt_report.json"
        --max-summary-deopt-rate-pct "$DEOPT_WARN_MAX_SUMMARY_DEOPT_RATE_PCT"
        --max-summary-guard-fail-rate-pct "$DEOPT_WARN_MAX_SUMMARY_GUARD_FAIL_RATE_PCT"
        --max-total-clones "$DEOPT_WARN_MAX_TOTAL_CLONES"
        --max-scenario-clones "$DEOPT_WARN_MAX_SCENARIO_CLONES"
        --max-unknown-deopt-reasons "$DEOPT_WARN_MAX_UNKNOWN_DEOPT_REASONS"
        --max-unknown-guard-reasons "$DEOPT_WARN_MAX_UNKNOWN_GUARD_REASONS"
        --min-total-hits-for-rate-checks "$DEOPT_WARN_MIN_TOTAL_HITS_FOR_RATE_CHECKS"
        --out-json "$OUT_DIR/deopt_warn_report.json"
        --out-md "$OUT_DIR/deopt_warn_report.md"
    )
    if [[ "$DEOPT_WARN_ENFORCE" == "1" ]]; then
        deopt_warn_args+=(--enforce)
    fi
    set +e
    python3 "${deopt_warn_args[@]}"
    deopt_warn_rc=$?
    set -e
    if [[ "$deopt_warn_rc" -ne 0 ]]; then
        if [[ "$DEOPT_WARN_ENFORCE" == "1" ]]; then
            FAILED=1
        else
            echo "[perf] WARN: deopt warn gate failed (observe-only, set DEOPT_WARN_ENFORCE=1 to enforce)"
        fi
    fi
fi

if [[ "$FAILED" -ne 0 ]]; then
    update_perf_status_best_effort
    echo "[perf] Performance contract failed (speedup gate, hard limit, or strict soft regression)." >&2
    exit 1
fi

if [[ "$ENABLE_TREND_REPORT" == "1" ]]; then
    run_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    run_id="${GITHUB_RUN_ID:-local}"
    run_attempt="${GITHUB_RUN_ATTEMPT:-0}"
    trend_run_dir="${PERF_TREND_HISTORY_ROOT}/${run_stamp}_${run_id}_${run_attempt}"
    mkdir -p "$trend_run_dir"

    copied=0
    if [[ -f "$OUT_DIR/slope_report.json" ]]; then
        cp "$OUT_DIR/slope_report.json" "$trend_run_dir/slope_report.json"
        copied=1
    fi
    if [[ -f "$OUT_DIR/slope_report.md" ]]; then
        cp "$OUT_DIR/slope_report.md" "$trend_run_dir/slope_report.md"
    fi
    if [[ -f "$OUT_DIR/slope_report_rs_shadow.json" ]]; then
        cp "$OUT_DIR/slope_report_rs_shadow.json" "$trend_run_dir/slope_report_rs_shadow.json"
    fi
    if [[ -f "$OUT_DIR/slope_report_rs_shadow.md" ]]; then
        cp "$OUT_DIR/slope_report_rs_shadow.md" "$trend_run_dir/slope_report_rs_shadow.md"
    fi
    if [[ -f "$OUT_DIR/slope_report_rs_shadow_compare.txt" ]]; then
        cp "$OUT_DIR/slope_report_rs_shadow_compare.txt" "$trend_run_dir/slope_report_rs_shadow_compare.txt"
    fi
    if [[ -f "$OUT_DIR/slope_report_py_shadow.json" ]]; then
        cp "$OUT_DIR/slope_report_py_shadow.json" "$trend_run_dir/slope_report_py_shadow.json"
    fi
    if [[ -f "$OUT_DIR/slope_report_py_shadow.md" ]]; then
        cp "$OUT_DIR/slope_report_py_shadow.md" "$trend_run_dir/slope_report_py_shadow.md"
    fi
    if [[ -f "$OUT_DIR/slope_report_py_shadow_compare.txt" ]]; then
        cp "$OUT_DIR/slope_report_py_shadow_compare.txt" "$trend_run_dir/slope_report_py_shadow_compare.txt"
    fi
    if [[ -f "$OUT_DIR/slope_report_shadow_compare.json" ]]; then
        cp "$OUT_DIR/slope_report_shadow_compare.json" "$trend_run_dir/slope_report_shadow_compare.json"
    fi
    if [[ -f "$OUT_DIR/slope_report_shadow_compare.txt" ]]; then
        cp "$OUT_DIR/slope_report_shadow_compare.txt" "$trend_run_dir/slope_report_shadow_compare.txt"
    fi
    if [[ -f "$OUT_DIR/perf_report.json" ]]; then
        cp "$OUT_DIR/perf_report.json" "$trend_run_dir/perf_report.json"
    fi
    if [[ -f "$OUT_DIR/perf_report.md" ]]; then
        cp "$OUT_DIR/perf_report.md" "$trend_run_dir/perf_report.md"
    fi
    if [[ "$ENABLE_FIXED_COST_GATE" == "1" && -f "$OUT_DIR/fixed_cost_report.json" ]]; then
        cp "$OUT_DIR/fixed_cost_report.json" "$trend_run_dir/fixed_cost_report.json"
    fi
    if [[ "$ENABLE_FIXED_COST_GATE" == "1" && -f "$OUT_DIR/fixed_cost_report.md" ]]; then
        cp "$OUT_DIR/fixed_cost_report.md" "$trend_run_dir/fixed_cost_report.md"
    fi
    if [[ "$ENABLE_DEOPT_REPORT" == "1" && -f "$OUT_DIR/deopt_report.json" ]]; then
        cp "$OUT_DIR/deopt_report.json" "$trend_run_dir/deopt_report.json"
    fi
    if [[ "$ENABLE_DEOPT_REPORT" == "1" && -f "$OUT_DIR/deopt_report.md" ]]; then
        cp "$OUT_DIR/deopt_report.md" "$trend_run_dir/deopt_report.md"
    fi
    if [[ "$ENABLE_DEOPT_WARN_GATE" == "1" && -f "$OUT_DIR/deopt_warn_report.json" ]]; then
        cp "$OUT_DIR/deopt_warn_report.json" "$trend_run_dir/deopt_warn_report.json"
    fi
    if [[ "$ENABLE_DEOPT_WARN_GATE" == "1" && -f "$OUT_DIR/deopt_warn_report.md" ]]; then
        cp "$OUT_DIR/deopt_warn_report.md" "$trend_run_dir/deopt_warn_report.md"
    fi

    if [[ "$copied" == "1" ]]; then
        echo "[perf] Build trend report (last ${PERF_TREND_LIMIT} runs)"
        set +e
        python3 "$PERF_TREND_SCRIPT" \
            --artifacts-root "$PERF_TREND_HISTORY_ROOT" \
            --limit "$PERF_TREND_LIMIT" \
            --out-json "$OUT_DIR/trend_report.json" \
            --out-md "$OUT_DIR/trend_report.md"
        trend_rc=$?
        set -e
        if [[ "$trend_rc" -ne 0 ]]; then
            echo "[perf] WARN: trend report generation failed (rc=${trend_rc})"
        fi
    else
        echo "[perf] WARN: skip trend report (no slope_report.json in $OUT_DIR)"
    fi
fi

if [[ "$ENABLE_STABILITY_WINDOW_GATE" == "1" ]]; then
    if [[ -f "$OUT_DIR/trend_report.json" ]]; then
        echo "[perf] Evaluate stability window gate"
        stability_args=(
            "$STABILITY_WINDOW_SCRIPT"
            --trend-json "$OUT_DIR/trend_report.json"
            --window "$STABILITY_WINDOW_SIZE"
            --min-runs "$STABILITY_WINDOW_MIN_RUNS"
            --max-retryable-pct "$STABILITY_WINDOW_MAX_RETRYABLE_PCT"
            --max-hard-count "$STABILITY_WINDOW_MAX_HARD_COUNT"
            --required-rules "$STABILITY_WINDOW_REQUIRED_RULES"
            --min-rule-hit-pct "$STABILITY_WINDOW_MIN_RULE_HIT_PCT"
            --min-shadow-match-pct "$STABILITY_WINDOW_MIN_SHADOW_MATCH_PCT"
            --out-json "$OUT_DIR/stability_window_report.json"
            --out-md "$OUT_DIR/stability_window_report.md"
        )
        if [[ "$STABILITY_WINDOW_REQUIRE_SHADOW_MATCH" == "1" ]]; then
            stability_args+=(--require-shadow-match)
        fi
        if [[ "$STABILITY_WINDOW_FAIL_ON_INSUFFICIENT_RUNS" == "1" ]]; then
            stability_args+=(--fail-on-insufficient-runs)
        fi
        set +e
        python3 "${stability_args[@]}"
        stability_rc=$?
        set -e
        if [[ "$stability_rc" -ne 0 ]]; then
            if [[ "$STABILITY_WINDOW_ENFORCE" == "1" ]]; then
                FAILED=1
            else
                echo "[perf] WARN: stability window gate failed (observe-only, set STABILITY_WINDOW_ENFORCE=1 to enforce)"
            fi
        fi
    else
        echo "[perf] WARN: skip stability window gate (missing $OUT_DIR/trend_report.json)"
    fi
fi

update_perf_status_best_effort

if [[ "$FAILED" -ne 0 ]]; then
    echo "[perf] Performance contract failed (stability window)." >&2
    exit 1
fi
