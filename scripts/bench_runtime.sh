#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${BIN_DIR:-$ROOT_DIR/target/perf/runtime_baseline/bin}"

echo "[bench] Pinning CPU: taskset -c 0"
echo "[bench] Setting governor to performance (requires sudo):"
echo "  sudo cpupower frequency-set -g performance"
echo "  # or"
echo "  sudo cpufreq-set -g performance"
echo

ITERS="${ITERS:-200}"
WARMUP_MS="${WARMUP_MS:-100}"
REPS="${REPS:-50}"

mkdir -p "$BIN_DIR"

echo "[bench] Build release with native CPU"
RUSTFLAGS="-C target-cpu=native" cargo build -p naux --release

echo
echo "[bench] Naux runtime-only benchmark (JIT)"
taskset -c 0 "$ROOT_DIR/target/release/naux" dev benchrt naux-lang/examples/bench_sum_dense.nx --engine=jit --iters="$ITERS" --warmup-ms="$WARMUP_MS"
taskset -c 0 "$ROOT_DIR/target/release/naux" dev benchrt naux-lang/examples/bench_list_update.nx --engine=jit --iters="$ITERS" --warmup-ms="$WARMUP_MS"
taskset -c 0 "$ROOT_DIR/target/release/naux" dev benchrt naux-lang/examples/bench_dot_product.nx --engine=jit --iters="$ITERS" --warmup-ms="$WARMUP_MS"
taskset -c 0 "$ROOT_DIR/target/release/naux" dev benchrt naux-lang/examples/bench_map_get_cmp_branch.nx --engine=jit --iters="$ITERS" --warmup-ms="$WARMUP_MS"
taskset -c 0 "$ROOT_DIR/target/release/naux" dev benchrt naux-lang/examples/bench_map_get_mul_acc.nx --engine=jit --iters="$ITERS" --warmup-ms="$WARMUP_MS"

echo
echo "[bench] C baseline (same algorithm)"
cc -O3 -march=native -o "$BIN_DIR/bench_sum_dense" "$ROOT_DIR/benchmarks/c/bench_sum_dense.c" -lm
taskset -c 0 "$BIN_DIR/bench_sum_dense" 100000 "$ITERS" "$WARMUP_MS" "$REPS"
cc -O3 -march=native -o "$BIN_DIR/bench_list_update" "$ROOT_DIR/benchmarks/c/bench_list_update.c" -lm
taskset -c 0 "$BIN_DIR/bench_list_update" 100000 "$ITERS" "$WARMUP_MS" "$REPS"
cc -O3 -march=native -o "$BIN_DIR/bench_dot_product" "$ROOT_DIR/benchmarks/c/bench_dot_product.c" -lm
taskset -c 0 "$BIN_DIR/bench_dot_product" 100000 "$ITERS" "$WARMUP_MS" "$REPS"
