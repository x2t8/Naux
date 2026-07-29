# Benchmarks (Runtime-only Baseline)

Mục tiêu: đo **runtime-only** (không tính parse/typecheck/compile), có **median + p95**, warmup tối thiểu 100ms, pin CPU core và governor.

## Checklist môi trường

- Pin CPU core: `taskset -c 0`
- Governor: `performance`
  - `sudo cpupower frequency-set -g performance`
  - hoặc `sudo cpufreq-set -g performance`
- Tắt logging/debug output (đã mặc định trong `benchrt`).

## Cross-language bundle chuẩn

Đây là command ưu tiên để so Naux với C, C++, Go, Rust và Zig:

```bash
CPU_CORE=0 N=100000 REPS=50 ITERS=50 WARMUP_MS=100 \
    ./scripts/bench_cross_language.sh
```

Script này:

- sinh bản benchmark Naux tạm thời với đúng cùng `N` và `REPS`
- build toàn bộ binary vào `target/perf/`, không ghi build artifact vào source tree
- đo cùng timed region: cấp phát input, khởi tạo, chạy kernel và tính cả
  explicit reclamation ở implementation có thao tác giải phóng xác định
- kiểm tra checksum Naux/VM semantics với từng baseline trước khi chấp nhận số đo
- tính CV trên toàn bộ sample của từng implementation; CV trên `5%` chỉ được
  coi là observation và tự động chặn claim
- ghi toolchain, CPU pinning, governor, turbo policy, Git SHA và dirty state
- ghi CPU model, physical/logical cores, RAM, target triple/features, timestamp,
  sample/outlier policy và command tái lập
- xuất `target/perf/cross_language/cross_language.{json,md,tsv}`

Chỉ được dùng artifact để công bố claim khi report có `claim.eligible=true`. Có thể
đặt `ENFORCE_CLAIM_ENV=1` để command fail nếu môi trường chưa đạt policy.
Claim eligibility mặc định còn yêu cầu ít nhất `30` sample/implementation,
warmup `100ms`, worktree sạch và đầy đủ fingerprint.

Sau một run đủ điều kiện, tạo deterministic evidence bundle:

```bash
python3 scripts/perf_claim_bundle.py
sha256sum -c target/perf/claims/*.tar.sha256
python3 scripts/perf_claim_bundle.py \
    --verify target/perf/claims/naux-performance-evidence-<sha>.tar
```

Packager từ chối fail-closed nếu report không eligible, thiếu một trong `24`
benchmark/implementation rows, checksum lệch, CV vượt ngưỡng, thiếu Zig,
fingerprint/Git SHA không hợp lệ, checkout hiện tại khác SHA hoặc dirty, hay
thiếu log/source evidence. Packager cũng từ chối nếu workload yêu cầu JIT nhưng
fallback về VM, không tạo trace, hoặc `branch_mix` thoát khỏi native forward
control flow. Bundle `.tar` chứa report, toàn bộ log, benchmark sources,
harness, manifest SHA-256 và command tái lập.

Khi đủ trend/stability evidence, claim readiness chỉ được chấp nhận qua
aggregator:

```bash
python3 scripts/perf_m1_readiness.py \
    --trend-json target/perf/trend_report.json \
    --stability-json target/perf/stability_window_report.json \
    --bundle target/perf/claims/naux-performance-evidence-<sha>.tar
```

Gate này yêu cầu 10 run pass liên tiếp, shadow match/coverage 100%, Rust là
primary thật trên runner kiểm soát không fallback, và bundle cùng Git SHA.

Zig là baseline tùy theo toolchain: source chuẩn nằm ở
`benchmarks/zig/bench_baselines.zig`. Source đã được compile và checksum-smoke
với Zig `0.16.0`; Zig chỉ là compiler cho baseline so sánh, không phải dependency
của compiler/runtime Naux. Khi có `zig` trong `PATH`, bundle tự build
`ReleaseFast`, chạy bốn workload và yêu cầu đủ 24 hàng parity/performance. Nếu
toolchain chưa có, report ghi `source-ready/toolchain-missing`, chỉ có 20 hàng từ
C/C++/Go/Rust/Naux và thêm blocker nên artifact không đủ điều kiện công bố claim.

Schema-v2 hiện ghi thêm `naux_execution` cho từng workload: requested engine,
fallback, trace count, deopt, internal side exits và static branches. Smoke cục
bộ với Zig `0.16.0` có `24/24` hàng, toàn bộ checksum match và native-branch
certificate đạt. Artifact này không dùng để claim vì governor/turbo/dirty-state
chưa đạt policy.

## Naux runtime-only

```bash
RUSTFLAGS="-C target-cpu=native" cargo build -p naux --release
taskset -c 0 ./target/release/naux dev benchrt naux-lang/examples/bench_sum_dense.nx --engine=jit --iters=200 --warmup-ms=100
taskset -c 0 ./target/release/naux dev benchrt naux-lang/examples/bench_list_update.nx --engine=jit --iters=200 --warmup-ms=100
taskset -c 0 ./target/release/naux dev benchrt naux-lang/examples/bench_dot_product.nx --engine=jit --iters=200 --warmup-ms=100
taskset -c 0 ./target/release/naux dev benchrt naux-lang/examples/bench_branch_mix.nx --engine=jit --iters=200 --warmup-ms=100
```

### Native internal-branch diagnostic

`bench_internal_branch_handoff.nx` (tên lịch sử) stresses a hot forward branch
that changes direction near the end of every loop invocation:

```bash
taskset -c 0 ./target/release/naux dev benchrt \
    naux-lang/examples/bench_internal_branch_handoff.nx \
    --engine=jit --iters=50 --warmup-ms=100 --json
```

Forward `if`/`if-else` edges now remain inside one native trace. The JSON proves:

- `trace_count=1` and `total_static_branches>0`;
- `total_internal_side_exits=0`;
- `total_deopts=0` and `total_runtime_deopts=0`.

`branch_mix` extends the same invariant to an alternating nested `if`/`if-else`
shape in the official cross-language bundle. Backward internal edges from
nested loops remain rejected to prevent trace explosion.

Output mẫu:

```
~ NAUX BENCH (runtime-only) ~
[BENCH] median=... ns/op (.. ops/sec), p95=... ns/op over 200 runs (warmup 100 ms, ... iters) engine=jit
```

## C baseline (cùng thuật toán)

```bash
mkdir -p target/perf/manual/bin
cc -O3 -march=native -o target/perf/manual/bin/bench_sum_dense benchmarks/c/bench_sum_dense.c -lm
taskset -c 0 ./target/perf/manual/bin/bench_sum_dense 100000 200 100 50
cc -O3 -march=native -o target/perf/manual/bin/bench_list_update benchmarks/c/bench_list_update.c -lm
taskset -c 0 ./target/perf/manual/bin/bench_list_update 100000 200 100 50
cc -O3 -march=native -o target/perf/manual/bin/bench_dot_product benchmarks/c/bench_dot_product.c -lm
taskset -c 0 ./target/perf/manual/bin/bench_dot_product 100000 200 100 50
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
