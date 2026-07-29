#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ITERS="${ITERS:-200}"
WARMUP_MS="${WARMUP_MS:-100}"
ENGINE="${ENGINE:-jit}"
PIN_CPU="${PIN_CPU:-0}"
ALLOW_INPUT_MISMATCH="${ALLOW_INPUT_MISMATCH:-0}"

# Current Naux benchmark constants in naux-lang/examples/bench_dot_product.nx:
# n=100000, reps=50, data initialized as list_range(n) (equivalent seed=0).
NAUX_FIXED_N=100000
NAUX_FIXED_REPS=50
NAUX_FIXED_SEED=0

N="${N:-$NAUX_FIXED_N}"
REPS="${REPS:-$NAUX_FIXED_REPS}"
SEED="${SEED:-$NAUX_FIXED_SEED}"

# Hard requirement from current performance policy:
# Naux should beat C++ variant 2 (vectorization-friendly).
REQUIRE_NAUX_BEAT_V2="${REQUIRE_NAUX_BEAT_V2:-1}"

# "Near AVX2 ceiling" soft target when comparing against variant 3.
# ratio = v3_median / naux_median. >= 0.85 means Naux is within ~15%.
MIN_V3_TO_NAUX_RATIO_WARN="${MIN_V3_TO_NAUX_RATIO_WARN:-0.85}"

CPP_SRC="$ROOT_DIR/benchmarks/cpp/bench_dot_product_cpp.cpp"
CPP_BIN_DIR="${CPP_BIN_DIR:-$ROOT_DIR/target/perf/cpp_variants/bin}"

parse_median_ns() {
    sed -n 's/.*median=\([0-9][0-9]*\) ns\/op.*/\1/p' | head -n 1
}

run_pinned() {
    if command -v taskset >/dev/null 2>&1; then
        taskset -c "$PIN_CPU" "$@"
    else
        "$@"
    fi
}

if [[ ! -f "$CPP_SRC" ]]; then
    echo "[bench] Missing source: $CPP_SRC" >&2
    exit 1
fi

mkdir -p "$CPP_BIN_DIR"

if [[ "$ALLOW_INPUT_MISMATCH" != "1" ]]; then
    if [[ "$N" != "$NAUX_FIXED_N" || "$REPS" != "$NAUX_FIXED_REPS" || "$SEED" != "$NAUX_FIXED_SEED" ]]; then
        echo "[bench] Input mismatch with current Naux benchmark constants." >&2
        echo "[bench] Expected: N=$NAUX_FIXED_N REPS=$NAUX_FIXED_REPS SEED=$NAUX_FIXED_SEED" >&2
        echo "[bench] Got: N=$N REPS=$REPS SEED=$SEED" >&2
        echo "[bench] Set ALLOW_INPUT_MISMATCH=1 only if you intentionally compare different workloads." >&2
        exit 1
    fi
fi

echo "[bench] Build Naux release (-C target-cpu=native)"
(
    cd "$ROOT_DIR"
    RUSTFLAGS="-C target-cpu=native" cargo build -p naux --release >/dev/null
)

echo
echo "[bench] Run Naux dot_product runtime-only"
NAUX_OUT="$(run_pinned "$ROOT_DIR/target/release/naux" \
    dev benchrt "$ROOT_DIR/naux-lang/examples/bench_dot_product.nx" \
    --engine="$ENGINE" --iters="$ITERS" --warmup-ms="$WARMUP_MS")"
echo "$NAUX_OUT"
NAUX_MEDIAN="$(printf '%s\n' "$NAUX_OUT" | parse_median_ns)"
if [[ -z "$NAUX_MEDIAN" ]]; then
    echo "[bench] Failed to parse Naux median" >&2
    exit 1
fi

echo
echo "[bench] Build C++ dot variants"
g++ -O3 -march=native -std=c++20 -DNAUX_DOT_VARIANT=1 \
    -o "$CPP_BIN_DIR/bench_dot_product_v1_naive" "$CPP_SRC"
g++ -O3 -march=native -ffast-math -fno-math-errno -std=c++20 -DNAUX_DOT_VARIANT=2 \
    -o "$CPP_BIN_DIR/bench_dot_product_v2_vec" "$CPP_SRC"
g++ -O3 -march=native -mavx2 -mfma -ffast-math -fno-math-errno -std=c++20 -DNAUX_DOT_VARIANT=3 \
    -o "$CPP_BIN_DIR/bench_dot_product_v3_avx2" "$CPP_SRC"

echo
echo "[bench] Run C++ variants (n=$N iters=$ITERS warmup=${WARMUP_MS}ms reps=$REPS seed=$SEED)"
V1_OUT="$(run_pinned "$CPP_BIN_DIR/bench_dot_product_v1_naive" "$N" "$ITERS" "$WARMUP_MS" "$REPS" "$SEED")"
V2_OUT="$(run_pinned "$CPP_BIN_DIR/bench_dot_product_v2_vec" "$N" "$ITERS" "$WARMUP_MS" "$REPS" "$SEED")"
V3_OUT="$(run_pinned "$CPP_BIN_DIR/bench_dot_product_v3_avx2" "$N" "$ITERS" "$WARMUP_MS" "$REPS" "$SEED")"
echo "$V1_OUT"
echo "$V2_OUT"
echo "$V3_OUT"

V1_MEDIAN="$(printf '%s\n' "$V1_OUT" | parse_median_ns)"
V2_MEDIAN="$(printf '%s\n' "$V2_OUT" | parse_median_ns)"
V3_MEDIAN="$(printf '%s\n' "$V3_OUT" | parse_median_ns)"
if [[ -z "$V1_MEDIAN" || -z "$V2_MEDIAN" || -z "$V3_MEDIAN" ]]; then
    echo "[bench] Failed to parse C++ median(s)" >&2
    exit 1
fi

V1_SPEEDUP="$(awk -v c="$V1_MEDIAN" -v n="$NAUX_MEDIAN" 'BEGIN { printf "%.3f", c / n }')"
V2_SPEEDUP="$(awk -v c="$V2_MEDIAN" -v n="$NAUX_MEDIAN" 'BEGIN { printf "%.3f", c / n }')"
V3_SPEEDUP="$(awk -v c="$V3_MEDIAN" -v n="$NAUX_MEDIAN" 'BEGIN { printf "%.3f", c / n }')"

echo
echo "| target | median ns/op | C++/Naux speedup |"
echo "|---|---:|---:|"
echo "| Naux JIT | $NAUX_MEDIAN | 1.000 |"
echo "| C++ v1 naive | $V1_MEDIAN | $V1_SPEEDUP |"
echo "| C++ v2 vec-friendly | $V2_MEDIAN | $V2_SPEEDUP |"
echo "| C++ v3 AVX2 intrinsics | $V3_MEDIAN | $V3_SPEEDUP |"

STATUS=0
if [[ "$REQUIRE_NAUX_BEAT_V2" == "1" ]]; then
    if (( NAUX_MEDIAN >= V2_MEDIAN )); then
        echo "[bench] FAIL: Naux does not beat C++ variant 2 (median)." >&2
        STATUS=1
    else
        echo "[bench] PASS: Naux beats C++ variant 2 (median)."
    fi
fi

if (( NAUX_MEDIAN > V3_MEDIAN )); then
    if ! awk -v r="$V3_SPEEDUP" -v min="$MIN_V3_TO_NAUX_RATIO_WARN" 'BEGIN { exit !(r >= min) }'; then
        echo "[bench] WARN: Naux is not near C++ variant 3 ceiling (ratio=$V3_SPEEDUP < $MIN_V3_TO_NAUX_RATIO_WARN)." >&2
    else
        echo "[bench] INFO: Naux is near C++ variant 3 ceiling (ratio=$V3_SPEEDUP)."
    fi
fi

exit "$STATUS"
