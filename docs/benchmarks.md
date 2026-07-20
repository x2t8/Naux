# Benchmarks (Runtime-only Baseline)

Mục tiêu: đo **runtime-only** (không tính parse/typecheck/compile), có **median + p95**, warmup tối thiểu 100ms, pin CPU core và governor.

## Checklist môi trường

- Pin CPU core: `taskset -c 0`
- Governor: `performance`
  - `sudo cpupower frequency-set -g performance`
  - hoặc `sudo cpufreq-set -g performance`
- Tắt logging/debug output (đã mặc định trong `benchrt`).

## Naux runtime-only

```bash
RUSTFLAGS="-C target-cpu=native" cargo build -p naux --release
taskset -c 0 ./target/release/naux dev benchrt naux-lang/examples/bench_sum_dense.nx --engine=jit --iters=200 --warmup-ms=100
taskset -c 0 ./target/release/naux dev benchrt naux-lang/examples/bench_list_update.nx --engine=jit --iters=200 --warmup-ms=100
taskset -c 0 ./target/release/naux dev benchrt naux-lang/examples/bench_dot_product.nx --engine=jit --iters=200 --warmup-ms=100
```

Output mẫu:

```
~ NAUX BENCH (runtime-only) ~
[BENCH] median=... ns/op (.. ops/sec), p95=... ns/op over 200 runs (warmup 100 ms, ... iters) engine=jit
```

## C baseline (cùng thuật toán)

```bash
cc -O3 -march=native -o benchmarks/c/bench_sum_dense benchmarks/c/bench_sum_dense.c
taskset -c 0 ./benchmarks/c/bench_sum_dense 100000 200 100 50
cc -O3 -march=native -o benchmarks/c/bench_list_update benchmarks/c/bench_list_update.c
taskset -c 0 ./benchmarks/c/bench_list_update 100000 200 100 50
cc -O3 -march=native -o benchmarks/c/bench_dot_product benchmarks/c/bench_dot_product.c
taskset -c 0 ./benchmarks/c/bench_dot_product 100000 200 100 50
```

## C++ baseline 3 variants (dot_product)

Mức khắt khe tăng dần:
- `v1_naive`: loop cơ bản.
- `v2_vec_friendly`: `__restrict__` + `#pragma GCC ivdep` + `-ffast-math`.
- `v3_avx2_intrinsics`: AVX2/FMA intrinsics (ceiling thực tế).

Script chuẩn:

```bash
ITERS=200 WARMUP_MS=100 ./scripts/bench_dot_cpp_variants.sh
```

Measurement discipline script này đang enforce:
- Warmup trước khi đo.
- Report bằng `median` + `p95` (không dùng mean).
- Cùng `n/reps/seed` cho cả Naux và C++ variants.
  - Hiện tại script enforce theo benchmark Naux đang cố định: `n=100000`, `reps=50`, `seed=0`.
  - Có thể bỏ enforce bằng `ALLOW_INPUT_MISMATCH=1` nếu cố ý so workload khác.
- Pin CPU bằng `taskset -c <PIN_CPU>` nếu có (`PIN_CPU` mặc định `0`).

Policy hiện tại:
- Hard gate: Naux phải thắng `v2_vec_friendly` theo median.
- Soft check: nếu thua `v3_avx2_intrinsics` thì phải "gần" (mặc định trong khoảng ~15%, cấu hình qua `MIN_V3_TO_NAUX_RATIO_WARN`).

## KPI (định nghĩa “thắng C”)

- So sánh **median** và **p95** (không dùng mean).
- Naux JIT nên dùng gate theo domain/benchmark thay vì một ngưỡng cứng cho tất cả.
  - Ví dụ: `sum_dense >= 1.2x`, `list_update >= 1.2x`, `dot_product >= 1.0x` trong giai đoạn hiện tại.
- Warmup tối thiểu 100ms trước đo.

## Script tự động

```bash
ITERS=200 WARMUP_MS=100 REPS=50 ./scripts/bench_runtime.sh
```

## CI performance contract

Workflow CI có job `perf-contract` dùng script:

```bash
./scripts/perf_contract_ci.sh
```

Job này:
- Build `naux` release với `-C target-cpu=native`.
- Chạy benchmark runtime-only của Naux và benchmark C đối chiếu.
- Thu thêm metric i-cache proxy từ trace: `trace code avg bytes`.
- Hard fail code-size:
  - `sum_dense`, `dot_product`: `<= 512B` (mặc định).
- Soft regression warning:
  - Cảnh báo khi `trace code avg bytes` tăng > `10%` so với baseline.
- Baseline file:
  - `benchmarks/perf_baseline.tsv`
- Xuất báo cáo:
  - `target/perf/perf_report.md`
  - `target/perf/perf_report.json`
  - log thô `target/perf/*.log`

Có thể cấu hình bằng env:
- `ITERS` (mặc định 10)
- `WARMUP_MS` (mặc định 100)
- `REPS` (mặc định 50)
- `ENGINE` (mặc định `jit`)
- `MIN_SPEEDUP` (mặc định 0, nếu đặt >0 thì fail khi `C/NAUX < MIN_SPEEDUP`)
- `MIN_SPEEDUP_SUM_DENSE` (tuỳ chọn, override cho benchmark `sum_dense`)
- `MIN_SPEEDUP_LIST_UPDATE` (tuỳ chọn, override cho benchmark `list_update`)
- `MIN_SPEEDUP_DOT_PRODUCT` (tuỳ chọn, override cho benchmark `dot_product`)
- `HARD_LIMIT_MATH_BYTES` (mặc định 512)
- `HARD_LIMIT_DEFAULT_BYTES` (mặc định 0 = tắt)
- `PERF_BASELINE_TSV` (mặc định `benchmarks/perf_baseline.tsv`)
- `SOFT_REGRESSION_PCT` (mặc định 10)
- `SOFT_REGRESSION_FAIL` (mặc định 0, nếu đặt 1 thì warning regression sẽ fail CI)
